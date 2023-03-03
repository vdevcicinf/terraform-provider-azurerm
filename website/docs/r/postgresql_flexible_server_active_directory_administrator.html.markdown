---
subcategory: "Database"
layout: "azurerm"
page_title: "Azure Resource Manager: azurerm_postgresql_flexible_server_active_directory_administrator"
description: |-
  Manages an Active Directory administrator on a PostgreSQL Flexible server
---

# azurerm_postgresql_flexible_server_active_directory_administrator

Allows you to set a user or group as the AD administrator for a PostgreSQL Flexible Server.

## Example Usage

```hcl
provider "azurerm" {
  features {}
}

provider "azuread" {

}

data "azurerm_client_config" "current" {}

resource "azuread_service_principal" "postgresql" {
  application_id = "5657e26c-cc92-45d9-bc47-9da6cfdb4ed9"
  use_existing   = true
}
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_postgresql_flexible_server" "example" {
  name                         = "example-psqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
  sku_name                     = "GP_Standard_D2s_v3"
  zone                         = "2"

  authentication {
    active_directory_auth_enabled = true
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  depends_on = [azuread_service_principal.postgresql]
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "example" {
  server_name         = azurerm_postgresql_flexible_server.example.name
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
  principal_name      = "example-sp"
  principal_type      = "ServicePrincipal"
}
```

## Argument Reference

The following arguments are supported:

* `server_name` - (Required) The name of the PostgreSQL Flexible Server on which to set the administrator. Changing this forces a new resource to be created.

* `resource_group_name` - (Required) The name of the resource group for the PostgreSQL Server. Changing this forces a new resource to be created.

* `object_id` - (Required) The object ID of a user, service principal or security group in the Azure Active Directory tenant set as the Flexible Server Admin. Changing this forces a new resource to be created.

* `tenant_id` - (Required) The Azure Tenant ID. Changing this forces a new resource to be created.

* `principal_name` - (Required) The name of Azure Active Directory principal. Changing this forces a new resource to be created.

* `principal_type` - (Required) The type of Azure Active Directory principal. Possible values are `Group`, `ServicePrincipal` and `User`. Changing this forces a new resource to be created.

## Attributes Reference

The following attributes are exported:

* `id` - The ID of the PostgreSQL Flexible Server Active Directory Administrator.

## Timeouts

The `timeouts` block allows you to specify [timeouts](https://www.terraform.io/language/resources/syntax#operation-timeouts) for certain actions:

* `create` - (Defaults to 30 minutes) Used when creating the PostgreSQL Flexible Server Active Directory Administrator.
* `update` - (Defaults to 30 minutes) Used when updating the PostgreSQL Flexible Server Active Directory Administrator.
* `read` - (Defaults to 5 minutes) Used when retrieving the PostgreSQL Flexible Server Active Directory Administrator.
* `delete` - (Defaults to 30 minutes) Used when deleting the PostgreSQL Flexible Server Active Directory Administrator.

## Import

A PostgreSQL Flexible Server Active Directory Administrator can be imported using the `resource id`, e.g.

```shell
terraform import azurerm_postgresql_flexible_server_active_directory_administrator.example /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myresourcegroup/providers/Microsoft.DBforPostgreSQL/flexibleServers/myserver/administrators/objectId
```
