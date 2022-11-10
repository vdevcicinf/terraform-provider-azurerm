package mssql

import (
	"context"
	"fmt"
	keyVaultParser "github.com/hashicorp/terraform-provider-azurerm/internal/services/keyvault/parse"
	keyVaultValidate "github.com/hashicorp/terraform-provider-azurerm/internal/services/keyvault/validate"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/preview/sql/mgmt/v5.0/sql"
	"github.com/hashicorp/terraform-provider-azurerm/internal/sdk"
	mssqlParse "github.com/hashicorp/terraform-provider-azurerm/internal/services/mssql/parse"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/mssql/validate"
	mssqlValidate "github.com/hashicorp/terraform-provider-azurerm/internal/services/mssql/validate"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/sql/parse"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
	"github.com/hashicorp/terraform-provider-azurerm/utils"
)

type MsSqlManagedInstanceTransparentDataEncryptionModel struct {
	ManagedInstanceId   string `tfschema:"managed_instance_id"`
	KeyVaultKeyId       string `tfschema:"key_vault_key_id"`
	AutoRotationEnabled bool   `tfschema:"auto_rotation_enabled"`
}

var _ sdk.Resource = MsSqlManagedInstanceTransparentDataEncryptionResource{}
var _ sdk.ResourceWithUpdate = MsSqlManagedInstanceTransparentDataEncryptionResource{}

type MsSqlManagedInstanceTransparentDataEncryptionResource struct{}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Attributes() map[string]*pluginsdk.Schema {
	return map[string]*pluginsdk.Schema{}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) ResourceType() string {
	return "azurerm_mssql_managed_instance_transparent_data_encryption"
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) ModelObject() interface{} {
	return &MsSqlManagedInstanceTransparentDataEncryptionModel{}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) IDValidationFunc() pluginsdk.SchemaValidateFunc {
	return validate.ManagedInstanceEncryptionProtectorID
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Arguments() map[string]*pluginsdk.Schema {
	return map[string]*pluginsdk.Schema{
		"managed_instance_id": {
			Type:         pluginsdk.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: mssqlValidate.ManagedInstanceID,
		},

		"key_vault_key_id": {
			Type:         pluginsdk.TypeString,
			Optional:     true,
			ValidateFunc: keyVaultValidate.NestedItemId,
		},

		"auto_rotation_enabled": {
			Type:     pluginsdk.TypeBool,
			Optional: true,
			Default:  false,
		},
	}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Create() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Timeout: 24 * time.Hour,
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			client := metadata.Client.MSSQL.ManagedInstanceEncryptionProtectorClient
			managedInstanceKeysClient := metadata.Client.MSSQL.ManagedInstanceKeysClient

			var model MsSqlManagedInstanceTransparentDataEncryptionModel
			if err := metadata.Decode(&model); err != nil {
				return fmt.Errorf("decoding: %+v", err)
			}

			managedInstanceId, err := parse.ManagedInstanceID(model.ManagedInstanceId)
			if err != nil {
				return err
			}

			id := mssqlParse.NewManagedInstanceEncryptionProtectorID(managedInstanceId.SubscriptionId, managedInstanceId.ResourceGroup, managedInstanceId.Name, "current")

			managedInstanceKeyName := ""
			managedInstanceKeyType := sql.ServerKeyTypeServiceManaged
			var managedInstanceKey sql.ManagedInstanceKey
			keyVaultKeyId := strings.TrimSpace(model.KeyVaultKeyId)
			// If it has content, then we assume it's a key vault key id
			if keyVaultKeyId != "" {
				// Update the server key type to AKV
				managedInstanceKeyType = sql.ServerKeyTypeAzureKeyVault

				// Set the SQL Server Key properties
				managedInstanceKeyProperties := sql.ManagedInstanceKeyProperties{
					ServerKeyType:       sql.ServerKeyTypeAzureKeyVault,
					URI:                 &keyVaultKeyId,
					AutoRotationEnabled: utils.Bool(model.AutoRotationEnabled),
				}
				managedInstanceKey.ManagedInstanceKeyProperties = &managedInstanceKeyProperties

				// Set the encryption protector properties
				keyId, err := keyVaultParser.ParseNestedItemID(keyVaultKeyId)
				if err != nil {
					return fmt.Errorf("Unable to parse key: %q: %+v", keyVaultKeyId, err)
				}

				// Make sure it's a key, if not, throw an error
				if keyId.NestedItemType == "keys" {
					keyName := keyId.Name
					keyVersion := keyId.Version

					// Extract the vault name from the keyvault base url
					idURL, err := url.ParseRequestURI(keyId.KeyVaultBaseUrl)
					if err != nil {
						return fmt.Errorf("Unable to parse key vault hostname: %s", keyId.KeyVaultBaseUrl)
					}

					hostParts := strings.Split(idURL.Host, ".")
					vaultName := hostParts[0]

					// Create the key path for the Encryption Protector. Format is: {vaultname}_{key}_{key_version}
					managedInstanceKeyName = fmt.Sprintf("%s_%s_%s", vaultName, keyName, keyVersion)
				} else {
					return fmt.Errorf("Key vault key id must be a reference to a key, but got: %s", keyId.NestedItemType)
				}
			}

			parameters := sql.ManagedInstanceEncryptionProtector{
				ManagedInstanceEncryptionProtectorProperties: &sql.ManagedInstanceEncryptionProtectorProperties{
					ServerKeyName:       &managedInstanceKeyName,
					ServerKeyType:       managedInstanceKeyType,
					AutoRotationEnabled: &model.AutoRotationEnabled,
				},
			}

			if managedInstanceKey.ManagedInstanceKeyProperties != nil {
				// Create a key on the server
				futureServers, err := managedInstanceKeysClient.CreateOrUpdate(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name, managedInstanceKeyName, managedInstanceKey)
				if err != nil {
					return fmt.Errorf("creating/updating managed instance key for %s: %+v", *managedInstanceId, err)
				}

				if err = futureServers.WaitForCompletionRef(ctx, managedInstanceKeysClient.Client); err != nil {
					return fmt.Errorf("waiting on update of %s: %+v", *managedInstanceId, err)
				}
			}

			//metadata.Logger.Infof("Creating %s", id)

			future, err := client.CreateOrUpdate(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name, parameters)
			if err != nil {
				return fmt.Errorf("creating %s: %+v", id, err)
			}

			if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
				return fmt.Errorf("waiting for creation of %s: %+v", id, err)
			}
			resp, err := client.Get(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name)
			print("\nID  " + *resp.ID)

			metadata.SetID(id)
			return nil
		},
	}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Update() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Timeout: 24 * time.Hour,
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			client := metadata.Client.MSSQL.ManagedInstanceEncryptionProtectorClient
			managedInstanceKeysClient := metadata.Client.MSSQL.ManagedInstanceKeysClient

			var model MsSqlManagedInstanceTransparentDataEncryptionModel
			if err := metadata.Decode(&model); err != nil {
				return fmt.Errorf("decoding: %+v", err)
			}

			managedInstanceId, err := parse.ManagedInstanceID(model.ManagedInstanceId)
			if err != nil {
				return err
			}

			id := mssqlParse.NewManagedInstanceEncryptionProtectorID(managedInstanceId.SubscriptionId, managedInstanceId.ResourceGroup, managedInstanceId.Name, "current")

			managedInstanceKeyName := ""
			managedInstanceKeyType := sql.ServerKeyTypeServiceManaged
			var managedInstanceKey sql.ManagedInstanceKey
			keyVaultKeyId := strings.TrimSpace(model.KeyVaultKeyId)
			// If it has content, then we assume it's a key vault key id
			if keyVaultKeyId != "" {
				// Update the server key type to AKV
				managedInstanceKeyType = sql.ServerKeyTypeAzureKeyVault

				// Set the SQL Server Key properties
				managedInstanceKeyProperties := sql.ManagedInstanceKeyProperties{
					ServerKeyType:       sql.ServerKeyTypeAzureKeyVault,
					URI:                 &keyVaultKeyId,
					AutoRotationEnabled: utils.Bool(model.AutoRotationEnabled),
				}
				managedInstanceKey.ManagedInstanceKeyProperties = &managedInstanceKeyProperties

				// Set the encryption protector properties
				keyId, err := keyVaultParser.ParseNestedItemID(keyVaultKeyId)
				if err != nil {
					return fmt.Errorf("Unable to parse key: %q: %+v", keyVaultKeyId, err)
				}

				// Make sure it's a key, if not, throw an error
				if keyId.NestedItemType == "keys" {
					keyName := keyId.Name
					keyVersion := keyId.Version

					// Extract the vault name from the keyvault base url
					idURL, err := url.ParseRequestURI(keyId.KeyVaultBaseUrl)
					if err != nil {
						return fmt.Errorf("Unable to parse key vault hostname: %s", keyId.KeyVaultBaseUrl)
					}

					hostParts := strings.Split(idURL.Host, ".")
					vaultName := hostParts[0]

					// Create the key path for the Encryption Protector. Format is: {vaultname}_{key}_{key_version}
					managedInstanceKeyName = fmt.Sprintf("%s_%s_%s", vaultName, keyName, keyVersion)
				} else {
					return fmt.Errorf("Key vault key id must be a reference to a key, but got: %s", keyId.NestedItemType)
				}
			}

			parameters := sql.ManagedInstanceEncryptionProtector{
				ManagedInstanceEncryptionProtectorProperties: &sql.ManagedInstanceEncryptionProtectorProperties{
					ServerKeyName:       &managedInstanceKeyName,
					ServerKeyType:       managedInstanceKeyType,
					AutoRotationEnabled: &model.AutoRotationEnabled,
				},
			}

			if managedInstanceKey.ManagedInstanceKeyProperties != nil {
				// Create a key on the server
				futureServers, err := managedInstanceKeysClient.CreateOrUpdate(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name, managedInstanceKeyName, managedInstanceKey)
				if err != nil {
					return fmt.Errorf("creating/updating managed instance key for %s: %+v", *managedInstanceId, err)
				}

				if err = futureServers.WaitForCompletionRef(ctx, managedInstanceKeysClient.Client); err != nil {
					return fmt.Errorf("waiting on update of %s: %+v", *managedInstanceId, err)
				}
			}

			//metadata.Logger.Infof("Creating %s", id)

			future, err := client.CreateOrUpdate(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name, parameters)
			if err != nil {
				return fmt.Errorf("creating %s: %+v", id, err)
			}

			if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
				return fmt.Errorf("waiting for creation of %s: %+v", id, err)
			}
			resp, err := client.Get(ctx, managedInstanceId.ResourceGroup, managedInstanceId.Name)
			print("\nID  " + *resp.ID)

			metadata.SetID(id)
			return nil
		},
	}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Read() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Timeout: 5 * time.Minute,
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			client := metadata.Client.MSSQL.ManagedInstanceEncryptionProtectorClient

			id, err := mssqlParse.ManagedInstanceEncryptionProtectorID(metadata.ResourceData.Id())
			if err != nil {
				return err
			}

			metadata.Logger.Infof("Decoding state for %s", id)
			var state MsSqlManagedInstanceTransparentDataEncryptionModel
			if err := metadata.Decode(&state); err != nil {
				return err
			}

			existing, err := client.Get(ctx, id.ResourceGroup, id.ManagedInstanceName)
			if err != nil {
				if utils.ResponseWasNotFound(existing.Response) {
					return metadata.MarkAsGone(id)
				}
				return fmt.Errorf("retrieving %s: %v", id, err)
			}

			keyVaultKeyId := ""
			autoRotationEnabled := false

			if props := existing.ManagedInstanceEncryptionProtectorProperties; props != nil {
				// Only set the key type if it's an AKV key. For service managed, we can omit the setting the key_vault_key_id
				if props.ServerKeyType == sql.ServerKeyTypeAzureKeyVault {
					log.Printf("[INFO] Setting Key Vault URI to %s", *props.URI)

					keyVaultKeyId = *props.URI

					// autoRotation is only for AKV keys
					if props.AutoRotationEnabled != nil {
						autoRotationEnabled = *props.AutoRotationEnabled
					}
				}
			}
			model := MsSqlManagedInstanceTransparentDataEncryptionModel{
				ManagedInstanceId:   id.ID(),
				KeyVaultKeyId:       keyVaultKeyId,
				AutoRotationEnabled: autoRotationEnabled,
			}

			return metadata.Encode(&model)
		},
	}
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) Delete() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Timeout: 24 * time.Hour,
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			// Note that encryption protector cannot be deleted. It can only be updated between AzureKeyVault
			// and SystemManaged. For safety, when this resource is deleted, we're resetting the key type
			// to service managed to prevent accidental lockout if someone were to delete the keys from key vault

			client := metadata.Client.MSSQL.ManagedInstanceEncryptionProtectorClient
			id, err := mssqlParse.ManagedInstanceEncryptionProtectorID(metadata.ResourceData.Id())
			if err != nil {
				return err
			}

			serverKeyName := ""

			// Service managed doesn't require a key name
			encryptionProtector := sql.ManagedInstanceEncryptionProtector{
				ManagedInstanceEncryptionProtectorProperties: &sql.ManagedInstanceEncryptionProtectorProperties{
					ServerKeyType: sql.ServerKeyTypeServiceManaged,
					ServerKeyName: &serverKeyName,
				},
			}

			futureEncryptionProtector, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.ManagedInstanceName, encryptionProtector)
			if err != nil {
				return fmt.Errorf("updating %s: %+v", id, err)
			}

			if err = futureEncryptionProtector.WaitForCompletionRef(ctx, client.Client); err != nil {
				return fmt.Errorf("waiting on update future for %s: %+v", id, err)
			}

			return nil
		},
	}
}
