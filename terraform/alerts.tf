resource "azurerm_monitor_action_group" "fa_errors" {
  name                = "${local.repository_name}-ag-errors"
  resource_group_name = azurerm_resource_group.app.name
  short_name          = "errors"

  email_receiver {
    name          = "creator"
    email_address = "daekjo@egmont.com"
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "example" {
  name                = "${local.repository_name}-qra-errors"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location

  evaluation_frequency = "PT30M"
  window_duration      = "PT30M"
  scopes               = [azurerm_application_insights.app_logging.id]
  severity             = 1

  criteria {
    query                   = <<-QUERY
      traces
      | where severityLevel >= 3
      QUERY
    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThan"
  }

  description           = "Errors detected in the ${local.repository_name} application"
  skip_query_validation = true

  action {
    action_groups = [azurerm_monitor_action_group.fa_errors.id]
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}
