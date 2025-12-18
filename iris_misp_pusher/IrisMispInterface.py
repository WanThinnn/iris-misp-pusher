#!/usr/bin/env python3
#
#
#  IRIS misp Source Code
#  Copyright (C) 2025 - iris-misp-pusher
#  thienlai159@gmail.com
#  Created by iris-misp-pusher - 2025-10-15
#
#  License MIT

# iris-misp-pusher/iris_misp_pusher/IrisMispInterface.py

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface

import iris_misp_pusher.IrisMispConfig as interface_conf
from iris_misp_pusher.misp_handler import misp_handler  # Import a file we just created

class IrisMispInterface(IrisModuleInterface):
    
    name = "IrisMISPPusher"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = interface_conf.module_type

    def register_hooks(self, module_id):
        """
        Register the hooks for the module
        """
        self.log.info(f"Registering hooks for module {module_id}")
        
        # Create a button labeled 'Push IOCs to MISP' on the IOC context menu (right-click)
        status = self.register_to_hook(
            module_id=module_id,
            iris_hook_name='on_manual_trigger_ioc',
            manual_hook_name='Push IOCs to MISP'
        )
        
        if status.is_failure():
            self.log.error(f"Failed to register hook: {status.get_message()}")
        else:
            self.log.info("Successfully registered 'Push IOCs to MISP' hook on IOC")

    def hooks_handler(self, hook_name, hook_ui_name, data):
        """
        This method is the entry point of the module.
        Handles IOC objects when user right-clicks and selects 'Push IOCs to MISP'
        """
        self.log.info(f"Hook {hook_name} triggered with {len(data)} IOC(s)")
        
        # Get configuration from UI
        conf = self.module_dict_conf
        misp_url = conf.get('misp_url')
        misp_key = conf.get('misp_key')
        event_ip_id = conf.get('event_ip_id')
        event_hash_id = conf.get('event_hash_id')
        verify_ssl = conf.get('verify_ssl', False)
        
        if not all([misp_url, misp_key, event_ip_id, event_hash_id]):
            self.log.error("MISP module is not configured properly.")
            return InterfaceStatus.I2Error(logs=list(self.message_queue), 
                                          data="MISP module not configured. Go to Advanced > Modules.")

        # The 'data' variable is a list containing the IOC objects that were selected
        newly_added_count = 0
        skipped_count = 0
        error_count = 0
        
        for ioc in data:
            value = ioc.ioc_value.strip()
            if not value:
                self.log.warning(f"Skipping empty IOC value")
                continue
            
            self.log.info(f"Processing IOC: {value}")
            
            # Check if exists in MISP first
            if misp_handler.check_misp_exists(self.log, value, misp_url, misp_key, verify_ssl):
                self.log.info(f"[SKIP] {value}: already exists in MISP")
                skipped_count += 1
                continue
            
            # Classify the IOC
            iris_type_name = ioc.ioc_type.type_name if ioc.ioc_type else None
            misp_type, event_id, category = misp_handler.classify_ioc(
                value, event_ip_id, event_hash_id, iris_type_name, ioc.ioc_tags
            )

            if not misp_type:
                self.log.error(f"[IGNORE] Could not classify IOC: {value}")
                error_count += 1
                continue
            
            # Prepare comment
            comment = ioc.ioc_description or ''
            
            # Add to MISP
            if misp_handler.add_to_misp(self.log, event_id, value, misp_type, category, 
                                       misp_url, misp_key, verify_ssl, comment, ioc.ioc_tags):
                newly_added_count += 1
                self.log.info(f"[SUCCESS] Added {value} to MISP")
            else:
                error_count += 1
                self.log.error(f"[FAILED] Could not add {value} to MISP")
        
        # Return a success message to the user
        msg = f"Push to MISP completed: {newly_added_count} added, {skipped_count} skipped (already exist), {error_count} failed."
        self.log.info(msg)
        
        # Update output files if configured and successful
        if newly_added_count > 0:
            self._update_output_files(conf, event_ip_id, event_hash_id, misp_url, misp_key, verify_ssl)
        
        if newly_added_count > 0 or skipped_count > 0:
            return InterfaceStatus.I2Success(logs=list(self.message_queue), data=data)
        else:
            return InterfaceStatus.I2Error(logs=list(self.message_queue), data=msg)
    
    def _update_output_files(self, conf, event_ip_id, event_hash_id, misp_url, misp_key, verify_ssl):
        """Cập nhật các file output với dữ liệu từ MISP sau khi push thành công"""
        www_user = conf.get('www_user', 'www-data:www-data')
        
        # Update IP-SRC file
        output_src = conf.get('output_src_path', '').strip()
        if output_src:
            self.log.info(f"Updating output file: {output_src}")
            src_ips = misp_handler.fetch_values_from_misp(
                self.log, "ip-src", event_ip_id, misp_url, misp_key, verify_ssl
            )
            if src_ips:
                misp_handler.update_output_file(self.log, output_src, src_ips, www_user)
        
        # Update IP-DST file
        output_dst = conf.get('output_dst_path', '').strip()
        if output_dst:
            self.log.info(f"Updating output file: {output_dst}")
            dst_ips = misp_handler.fetch_values_from_misp(
                self.log, "ip-dst", event_ip_id, misp_url, misp_key, verify_ssl
            )
            if dst_ips:
                misp_handler.update_output_file(self.log, output_dst, dst_ips, www_user)
        
        # Update Domain file
        output_domain = conf.get('output_domain_path', '').strip()
        if output_domain:
            self.log.info(f"Updating output file: {output_domain}")
            domains = misp_handler.fetch_values_from_misp(
                self.log, "domain", event_ip_id, misp_url, misp_key, verify_ssl
            )
            if domains:
                misp_handler.update_output_file(self.log, output_domain, domains, www_user)
        
        # Update URL file
        output_url = conf.get('output_url_path', '').strip()
        if output_url:
            self.log.info(f"Updating output file: {output_url}")
            urls = misp_handler.fetch_values_from_misp(
                self.log, "url", event_ip_id, misp_url, misp_key, verify_ssl
            )
            if urls:
                misp_handler.update_output_file(self.log, output_url, urls, www_user)

# import traceback
# from pathlib import Path

# import iris_interface.IrisInterfaceStatus as InterfaceStatus
# from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes

# import iris_misp_module.IrisMispConfig as interface_conf
# from iris_misp_module.misp_handler.misp_handler import MispHandler


# class IrisMispInterface(IrisModuleInterface):
#     """
#     Provide the interface between Iris and mispHandler
#     """
#     name = "IrisMispInterface"
#     _module_name = interface_conf.module_name
#     _module_description = interface_conf.module_description
#     _interface_version = interface_conf.interface_version
#     _module_version = interface_conf.module_version
#     _pipeline_support = interface_conf.pipeline_support
#     _pipeline_info = interface_conf.pipeline_info
#     _module_configuration = interface_conf.module_configuration
    
#     _module_type = IrisModuleTypes.module_processor
    
     
#     def register_hooks(self, module_id: int):
#         """
#         Registers all the hooks

#         :param module_id: Module ID provided by IRIS
#         :return: Nothing
#         """
#         self.module_id = module_id
#         module_conf = self.module_dict_conf
#         if module_conf.get('misp_on_create_hook_enabled'):
#             status = self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_create')
#             if status.is_failure():
#                 self.log.error(status.get_message())
#                 self.log.error(status.get_data())

#             else:
#                 self.log.info("Successfully registered on_postload_ioc_create hook")
#         else:
#             self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_ioc_create')

#         if module_conf.get('misp_on_update_hook_enabled'):
#             status = self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_update')
#             if status.is_failure():
#                 self.log.error(status.get_message())
#                 self.log.error(status.get_data())

#             else:
#                 self.log.info("Successfully registered on_postload_ioc_update hook")
#         else:
#             self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_ioc_update')

#         if module_conf.get('misp_manual_hook_enabled'):
#             status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_ioc',
#                                            manual_hook_name='Get misp insight')
#             if status.is_failure():
#                 self.log.error(status.get_message())
#                 self.log.error(status.get_data())

#             else:
#                 self.log.info("Successfully registered on_manual_trigger_ioc hook")

#         else:
#             self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_manual_trigger_ioc')


#     def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
#         """
#         Hooks handler table. Calls corresponding methods depending on the hooks name.

#         :param hook_name: Name of the hook which triggered
#         :param hook_ui_name: Name of the ui hook
#         :param data: Data associated with the trigger.
#         :return: Data
#         """

#         self.log.info(f'Received {hook_name}')
#         if hook_name in ['on_postload_ioc_create', 'on_postload_ioc_update', 'on_manual_trigger_ioc']:
#             status = self._handle_ioc(data=data)

#         else:
#             self.log.critical(f'Received unsupported hook {hook_name}')
#             return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

#         if status.is_failure():
#             self.log.error(f"Encountered error processing hook {hook_name}")
#             return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

#         self.log.info(f"Successfully processed hook {hook_name}")
#         return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))


#     def _handle_ioc(self, data) -> InterfaceStatus.IIStatus:
#         """
#         Handle the IOC data the module just received. The module registered
#         to on_postload hooks, so it receives instances of IOC object.
#         These objects are attached to a dedicated SQlAlchemy session so data can
#         be modified safely.

#         :param data: Data associated to the hook, here IOC object
#         :return: IIStatus
#         """

#         misp_handler = MispHandler(mod_config=self.module_dict_conf,
#                                server_config=self.server_dict_conf,
#                                logger=self.log)

#         in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

#         for element in data:
#             # Check that the IOC we receive is of type the module can handle and dispatch
#             if 'domain' in element.ioc_type.type_name:
#                 status = misp_handler.handle_domain(ioc=element)
#                 in_status = InterfaceStatus.merge_status(in_status, status)

#             #elif element.ioc_type.type_name in ['md5', 'sha224', 'sha256', 'sha512']:
#             #    status = misp_handler.handle_hash(ioc=element)
#             #    in_status = InterfaceStatus.merge_status(in_status, status)
#             #
#             # elif element.ioc_type.type_name in etc...

#             else:
#                 self.log.error(f'IOC type {element.ioc_type.type_name} not handled by misp module. Skipping')

#         return in_status(data=data)
    
