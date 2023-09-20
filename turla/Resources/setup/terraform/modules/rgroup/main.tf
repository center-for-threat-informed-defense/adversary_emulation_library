
resource "azurerm_resource_group" "resource_group" {
  name     = var.name
  location = var.location
  tags = {
    Description = tostring(try(var.description))
    Category    = tostring(try(var.category))
    Environment = tostring(try(var.environment))
    ChargeCode  = tostring(try(var.charge_code))
  }
}
