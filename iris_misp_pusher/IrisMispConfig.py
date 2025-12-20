#!/usr/bin/env python3
# iris-misp-pusher/iris_misp_pusher/IrisMispConfig.py

from iris_interface.IrisModuleInterface import IrisModuleTypes

# Module metadata
module_name = 'IrisMISPPusher'
module_description = "A module to push case IOCs to a MISP instance"
module_version = '0.1.0'
interface_version = 1.1
module_type = IrisModuleTypes.module_processor

# Pipeline support
pipeline_support = False
pipeline_info = {}

# Module configuration
module_configuration = [
        {
            "param_name": "misp_url",
            "param_human_name": "MISP URL",
            "param_description": "URL of the MISP instance (e.g., https://misp.cyberfortress.local)",
            "default": None,
            "mandatory": True,
            "type": "string"
        },
        {
            "param_name": "misp_key",
            "param_human_name": "MISP API Key",
            "param_description": "MISP Automation Key",
            "default": None,
            "mandatory": True,
            "type": "sensitive_string"
        },
        {
            "param_name": "event_ip_id",
            "param_human_name": "MISP Event ID for IPs/Domains",
            "param_description": "The MISP event ID to add network indicators to",
            "default": "",
            "mandatory": True,
            "type": "string"
        },
        {
            "param_name": "event_hash_id",
            "param_human_name": "MISP Event ID for Hashes/Files",
            "param_description": "The MISP event ID to add file indicators to",
            "default": "",
            "mandatory": True,
            "type": "string"
        },
        {
            "param_name": "verify_ssl",
            "param_human_name": "Verify SSL Certificate",
            "param_description": "Set to false to ignore SSL warnings",
            "default": False,
            "mandatory": True,
            "type": "bool"
        },
        # === Trigger Settings ===
        {
            "param_name": "misp_manual_hook_enabled",
            "param_human_name": "Manual triggers on IOCs",
            "param_description": "Set to True to enable 'Push IOCs to MISP' button in IOC context menu",
            "default": True,
            "mandatory": True,
            "type": "bool",
            "section": "Triggers"
        },
        {
            "param_name": "misp_on_create_hook_enabled",
            "param_human_name": "Auto-push on IOC create",
            "param_description": "Set to True to automatically push IOC to MISP when an IOC is created",
            "default": False,
            "mandatory": True,
            "type": "bool",
            "section": "Triggers"
        },
        {
            "param_name": "misp_on_update_hook_enabled",
            "param_human_name": "Auto-push on IOC update",
            "param_description": "Set to True to automatically push IOC to MISP when an IOC is updated",
            "default": False,
            "mandatory": True,
            "type": "bool",
            "section": "Triggers"
        }
]

# #!/usr/bin/env python3
# #
# #
# #  IRIS misp Source Code
# #  Copyright (C) 2025 - iris-misp-pusher
# #  thienlai159@gmail.com
# #  Created by iris-misp-pusher - 2025-10-15
# #
# #  License MIT

# module_name = "IrisMisp"
# module_description = ""
# interface_version = 1.1
# module_version = 1.0

# pipeline_support = False
# pipeline_info = {}


# module_configuration = [
#     {
#         "param_name": "misp_url",
#         "param_human_name": "misp URL",
#         "param_description": "",
#         "default": None,
#         "mandatory": True,
#         "type": "string"
#     },
#     {
#         "param_name": "misp_key",
#         "param_human_name": "misp key",
#         "param_description": "misp API key",
#         "default": None,
#         "mandatory": True,
#         "type": "sensitive_string"
#     },
    
#     {
#         "param_name": "misp_manual_hook_enabled",
#         "param_human_name": "Manual triggers on IOCs",
#         "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
#         "default": True,
#         "mandatory": True,
#         "type": "bool",
#         "section": "Triggers"
#     },
#     {
#         "param_name": "misp_on_create_hook_enabled",
#         "param_human_name": "Triggers automatically on IOC create",
#         "param_description": "Set to True to automatically add a misp insight each time an IOC is created",
#         "default": False,
#         "mandatory": True,
#         "type": "bool",
#         "section": "Triggers"
#     },
#     {
#         "param_name": "misp_on_update_hook_enabled",
#         "param_human_name": "Triggers automatically on IOC update",
#         "param_description": "Set to True to automatically add a misp insight each time an IOC is updated",
#         "default": False,
#         "mandatory": True,
#         "type": "bool",
#         "section": "Triggers"
#     },
#     {
#         "param_name": "misp_report_as_attribute",
#         "param_human_name": "Add misp report as new IOC attribute",
#         "param_description": "Creates a new attribute on the IOC, base on the misp report. Attributes are based "
#                              "on the templates of this configuration",
#         "default": True,
#         "mandatory": True,
#         "type": "bool",
#         "section": "Insights"
#     },# TODO: careful here, remove backslashes from \{\{ results| tojson(indent=4) \}\}
#     {
#         "param_name": "misp_domain_report_template",
#         "param_human_name": "Domain report template",
#         "param_description": "Domain report template used to add a new custom attribute to the target IOC",
#         "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
#                    "class=\"accordion\">\n            <h3>misp raw results</h3>\n\n           "
#                    " <div class=\"card\">\n                <div class=\"card-header "
#                    "collapsed\" id=\"drop_r_misp\" data-toggle=\"collapse\" "
#                    "data-target=\"#drop_raw_misp\" aria-expanded=\"false\" "
#                    "aria-controls=\"drop_raw_misp\" role=\"button\">\n                    <div "
#                    "class=\"span-icon\">\n                        <div "
#                    "class=\"flaticon-file\"></div>\n                    </div>\n              "
#                    "      <div class=\"span-title\">\n                        misp raw "
#                    "results\n                    </div>\n                    <div "
#                    "class=\"span-mode\"></div>\n                </div>\n                <div "
#                    "id=\"drop_raw_misp\" class=\"collapse\" aria-labelledby=\"drop_r_misp\" "
#                    "style=\"\">\n                    <div class=\"card-body\">\n              "
#                    "          <div id='misp_raw_ace'>\{\{ results| tojson(indent=4) \}\}</div>\n  "
#                    "                  </div>\n                </div>\n            </div>\n    "
#                    "    </div>\n    </div>\n</div> \n<script>\nvar misp_in_raw = ace.edit("
#                    "\"misp_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: "
#                    "30,\n});\nmisp_in_raw.setReadOnly(true);\nmisp_in_raw.setTheme("
#                    "\"ace/theme/tomorrow\");\nmisp_in_raw.session.setMode("
#                    "\"ace/mode/json\");\nmisp_in_raw.renderer.setShowGutter("
#                    "true);\nmisp_in_raw.setOption(\"showLineNumbers\", "
#                    "true);\nmisp_in_raw.setOption(\"showPrintMargin\", "
#                    "false);\nmisp_in_raw.setOption(\"displayIndentGuides\", "
#                    "true);\nmisp_in_raw.setOption(\"maxLines\", "
#                    "\"Infinity\");\nmisp_in_raw.session.setUseWrapMode("
#                    "true);\nmisp_in_raw.setOption(\"indentedSoftWrap\", "
#                    "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
#         "mandatory": False,
#         "type": "textfield_html",
#         "section": "Templates"
#     }
    
# ]