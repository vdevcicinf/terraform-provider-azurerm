package mssql_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-provider-azurerm/internal/acceptance"
	"github.com/hashicorp/terraform-provider-azurerm/internal/acceptance/check"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/mssql/parse"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
	"github.com/hashicorp/terraform-provider-azurerm/utils"
)

type MsSqlManagedInstanceTransparentDataEncryptionResource struct{}

func TestAccMsSqlManagedInstanceTransparentDataEncryption_keyVault(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_managed_instance_transparent_data_encryption", "test")
	r := MsSqlManagedInstanceTransparentDataEncryptionResource{}

	data.ResourceTest(t, r, []acceptance.TestStep{
		{
			Config: r.keyVault(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccMsSqlManagedInstanceTransparentDataEncryption_autoRotate(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_managed_instance_transparent_data_encryption", "test")
	r := MsSqlManagedInstanceTransparentDataEncryptionResource{}

	data.ResourceTest(t, r, []acceptance.TestStep{
		{
			Config: r.autoRotate(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.keyVault(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccMsSqlManagedInstanceTransparentDataEncryption_systemManaged(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_managed_instance_transparent_data_encryption", "test")
	r := MsSqlManagedInstanceTransparentDataEncryptionResource{}

	data.ResourceTest(t, r, []acceptance.TestStep{
		{
			Config: r.systemManaged(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("key_vault_key_id").HasValue(""),
			),
		},
		data.ImportStep(),
	})
}

func TestAccMsSqlManagedInstanceTransparentDataEncryption_update(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_managed_instance_transparent_data_encryption", "test")
	r := MsSqlManagedInstanceTransparentDataEncryptionResource{}

	// Test going from systemManaged to keyVault and back
	data.ResourceTest(t, r, []acceptance.TestStep{
		{
			Config: r.keyVault(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config: r.systemManaged(data),
			Check: acceptance.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("key_vault_key_id").HasValue(""),
			),
		},
		data.ImportStep(),
	})
}

func (MsSqlManagedInstanceTransparentDataEncryptionResource) Exists(ctx context.Context, client *clients.Client, state *pluginsdk.InstanceState) (*bool, error) {
	id, err := parse.ManagedInstanceEncryptionProtectorID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.MSSQL.ManagedInstanceEncryptionProtectorClient.Get(ctx, id.ResourceGroup, id.ManagedInstanceName)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			return nil, fmt.Errorf("%s does not exist", *id)
		}

		return nil, fmt.Errorf("reading %s: %v", *id, err)
	}

	return utils.Bool(resp.ID != nil), nil
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) baseKeyVault(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "test" {
  name                        = "acctestsqlserver%[2]s"
  location                    = azurerm_resource_group.test.location
  resource_group_name         = azurerm_resource_group.test.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Create", "Delete", "Update", "Purge",
    ]
  }

  access_policy {
    tenant_id = azurerm_mssql_managed_instance.test.identity[0].tenant_id
    object_id = azurerm_mssql_managed_instance.test.identity[0].principal_id

    key_permissions = [
      "Get", "WrapKey", "UnwrapKey", "List", "Create",
    ]
  }
}

resource "azurerm_key_vault_key" "generated" {
  name         = "keyVault"
  key_vault_id = azurerm_key_vault.test.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]

  depends_on = [
    azurerm_key_vault.test,
  ]
}
`, MsSqlManagedInstanceResource{}.identity(data), data.RandomStringOfLength(5))
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) keyVault(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_mssql_managed_instance_transparent_data_encryption" "test" {
  managed_instance_id        = azurerm_mssql_managed_instance.test.id
  key_vault_key_id = azurerm_key_vault_key.generated.id
}
`, r.baseKeyVault(data))
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) autoRotate(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_mssql_managed_instance_transparent_data_encryption" "test" {
  managed_instance_id             = azurerm_mssql_managed_instance.test.id
  key_vault_key_id      = azurerm_key_vault_key.generated.id
  auto_rotation_enabled = true
}
`, r.baseKeyVault(data))
}

func (r MsSqlManagedInstanceTransparentDataEncryptionResource) systemManaged(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_mssql_managed_instance_transparent_data_encryption" "test" {
  managed_instance_id = azurerm_mssql_managed_instance.test.id
}
`, MsSqlManagedInstanceResource{}.identity(data))
}
