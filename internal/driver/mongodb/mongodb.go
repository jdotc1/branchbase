package mongodb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/branchbase/branchbase/internal/driver"
	"github.com/branchbase/branchbase/internal/git"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Config holds connection parameters for MongoDB
type Config struct {
	URI           string
	BaseDatabase  string
	DefaultBranch string
}

type MongoDBDriver struct {
	cfg    Config
	client *mongo.Client
}

func init() {
	driver.Register("mongodb", func(params map[string]interface{}) (driver.Driver, error) {
		uri, _ := params["uri"].(string)
		baseDb, _ := params["base_database"].(string)
		defaultBranch, _ := params["default_branch"].(string)

		if uri == "" {
			host, _ := params["host"].(string)
			port, _ := params["port"].(int)
			user, _ := params["user"].(string)
			password, _ := params["password"].(string)
			if host != "" {
				if port <= 0 {
					port = 27017
				}
				if user != "" && password != "" {
					uri = fmt.Sprintf("mongodb://%s:%s@%s:%d", user, password, host, port)
				} else {
					uri = fmt.Sprintf("mongodb://%s:%d", host, port)
				}
			}
		}

		if uri == "" {
			return nil, fmt.Errorf("missing 'uri' for mongodb driver")
		}
		if baseDb == "" {
			return nil, fmt.Errorf("missing 'base_database' for mongodb driver")
		}

		return New(Config{
			URI:           uri,
			BaseDatabase:  baseDb,
			DefaultBranch: defaultBranch,
		})
	})
}

func New(cfg Config) (*MongoDBDriver, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.URI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	return &MongoDBDriver{
		cfg:    cfg,
		client: client,
	}, nil
}

// NewWithClient returns a MongoDBDriver using an existing mongo.Client (useful for testing or shared pools).
func NewWithClient(cfg Config, client *mongo.Client) *MongoDBDriver {
	return &MongoDBDriver{
		cfg:    cfg,
		client: client,
	}
}

func (d *MongoDBDriver) Name() string {
	return "mongodb"
}

func (d *MongoDBDriver) isBaseBranch(sanitized string) bool {
	def := strings.TrimSpace(d.cfg.DefaultBranch)
	if def == "" {
		return sanitized == "main" || sanitized == "master" || sanitized == "default"
	}
	return sanitized == git.SanitizeBranchName(def)
}

func (d *MongoDBDriver) formatDBName(branchName string) string {
	sanitized := git.SanitizeBranchName(branchName)
	if d.isBaseBranch(sanitized) {
		return d.cfg.BaseDatabase
	}
	return fmt.Sprintf("%s_%s", d.cfg.BaseDatabase, sanitized)
}

func (d *MongoDBDriver) Ping(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("mongodb client not initialized")
	}
	return d.client.Ping(ctx, nil)
}

func (d *MongoDBDriver) BranchExists(ctx context.Context, branchName string) (bool, error) {
	if d.client == nil {
		return false, fmt.Errorf("mongodb client not initialized")
	}
	dbName := d.formatDBName(branchName)
	names, err := d.client.ListDatabaseNames(ctx, bson.M{"name": dbName})
	if err != nil {
		return false, fmt.Errorf("failed to list databases: %w", err)
	}
	return len(names) > 0, nil
}

func (d *MongoDBDriver) CreateBranch(ctx context.Context, sourceBranch, targetBranch string) (retErr error) {
	if d.client == nil {
		return fmt.Errorf("mongodb client not initialized")
	}
	sourceDB := d.formatDBName(sourceBranch)
	targetDB := d.formatDBName(targetBranch)

	if sourceDB == targetDB {
		return fmt.Errorf("source and target branch database names are identical: %q", sourceDB)
	}

	srcDb := d.client.Database(sourceDB)
	targetDb := d.client.Database(targetDB)

	created := false
	defer func() {
		if retErr != nil && created {
			dropCtx, dropCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dropCancel()
			_ = targetDb.Drop(dropCtx)
		}
	}()

	colls, err := srcDb.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return fmt.Errorf("failed to list collections in source db %q: %w", sourceDB, err)
	}

	for _, collName := range colls {
		// Ignore system collections
		if strings.HasPrefix(collName, "system.") {
			continue
		}
		created = true
		srcColl := srcDb.Collection(collName)
		targetColl := targetDb.Collection(collName)

		// Use aggregation $out to copy to the target database
		pipeline := mongo.Pipeline{
			bson.D{{Key: "$match", Value: bson.D{}}},
			bson.D{{Key: "$out", Value: bson.D{
				{Key: "db", Value: targetDB},
				{Key: "coll", Value: collName},
			}}},
		}
		cursor, err := srcColl.Aggregate(ctx, pipeline)
		if err != nil {
			return fmt.Errorf("failed to clone collection %q: %w", collName, err)
		}
		if err := cursor.Close(ctx); err != nil {
			return fmt.Errorf("failed to close cursor: %w", err)
		}

		// Recreate non-default indexes on the target collection
		idxCursor, err := srcColl.Indexes().List(ctx)
		if err == nil {
			var indexModels []mongo.IndexModel
			for idxCursor.Next(ctx) {
				var doc bson.M
				if err := idxCursor.Decode(&doc); err == nil {
					name, _ := doc["name"].(string)
					if name == "_id_" {
						continue
					}
					keyDoc, ok := doc["key"]
					if !ok || keyDoc == nil {
						continue
					}
					opts := options.Index().SetName(name)
					if unique, ok := doc["unique"].(bool); ok {
						opts.SetUnique(unique)
					}
					if sparse, ok := doc["sparse"].(bool); ok {
						opts.SetSparse(sparse)
					}
					if expire, ok := doc["expireAfterSeconds"].(int32); ok {
						opts.SetExpireAfterSeconds(expire)
					}
					indexModels = append(indexModels, mongo.IndexModel{
						Keys:    keyDoc,
						Options: opts,
					})
				}
			}
			if err := idxCursor.Close(ctx); err != nil {
				return fmt.Errorf("failed to close index cursor on %q: %w", collName, err)
			}
			if len(indexModels) > 0 {
				if _, err := targetColl.Indexes().CreateMany(ctx, indexModels); err != nil {
					return fmt.Errorf("failed to recreate indexes on %q: %w", collName, err)
				}
			}
		}
	}
	return nil
}

func (d *MongoDBDriver) DeleteBranch(ctx context.Context, branchName string) error {
	if d.client == nil {
		return fmt.Errorf("mongodb client not initialized")
	}
	sanitized := git.SanitizeBranchName(branchName)
	if d.isBaseBranch(sanitized) {
		return fmt.Errorf("cannot delete protected base database %q", d.cfg.BaseDatabase)
	}
	dbName := d.formatDBName(branchName)
	if dbName == d.cfg.BaseDatabase {
		return fmt.Errorf("cannot delete protected base database %q", dbName)
	}
	return d.client.Database(dbName).Drop(ctx)
}

func (d *MongoDBDriver) ListBranches(ctx context.Context) ([]driver.BranchInfo, error) {
	if d.client == nil {
		return nil, fmt.Errorf("mongodb client not initialized")
	}
	dbs, err := d.client.ListDatabases(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}

	prefix := d.cfg.BaseDatabase + "_"
	var branches []driver.BranchInfo

	for _, db := range dbs.Databases {
		if db.Name == d.cfg.BaseDatabase {
			branches = append(branches, driver.BranchInfo{
				Name:        d.cfg.DefaultBranch,
				Database:    db.Name,
				SizeBytes:   db.SizeOnDisk,
				IsProtected: true,
			})
			continue
		}

		if strings.HasPrefix(db.Name, prefix) {
			branchName := strings.TrimPrefix(db.Name, prefix)
			branches = append(branches, driver.BranchInfo{
				Name:        branchName,
				Database:    db.Name,
				SizeBytes:   db.SizeOnDisk,
				IsProtected: false,
			})
		}
	}

	return branches, nil
}

func (d *MongoDBDriver) Close() error {
	if d.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.client.Disconnect(ctx)
}
