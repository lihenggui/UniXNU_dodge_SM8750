#!/usr/bin/env python3
"""Build or verify the offline CPH2653 GPU source candidate; never operate a phone."""
import argparse
import json
import subprocess

from native_driver_build import ROOT, NATIVE, require, sha, symbols
from prepare_ios16_display_cache import file_sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true', help='Verify current reports and actual artifacts without rebuilding')
    args = parser.parse_args()
    if not args.check_only:
        commands = ['prepare_gpu_tools.py', 'build_gpu_shader_tools.py', 'prepare_firmware_tools.py']
        if not (ROOT / '.cache/stock-cph2653-16.0.1.304/vendor.img').exists():
            commands.append('fetch_stock_gpu_inputs.py')
        commands += ['prepare_gpu_firmware.py', 'check_ios16_graphics.py', 'check_ios16_display.py', 'prepare_ios16_display_interface.py', 'check_iphone_legacy_subclass.py', 'prepare_ios16_display_lifecycle.py',
                     'check_display_interface_emulation.py', 'check_ios16_swap.py', 'prepare_ios16_swap_completion.py', 'prepare_ios16_refresh.py', 'prepare_ios16_request_fields.py', 'prepare_ios16_producer.py',
                     'prepare_ios16_display_cache.py', 'prepare_ios16_display_userland.py', 'audit_ios16_backend_contracts.py', 'prepare_ios16_surface.py', 'build_surface_backing.py',
                     'build_a830_backend.py', 'check_a830_backend.py', 'build_gpu_policy.py', 'build_gpu_board.py', 'build_diagnostic_console.py', 'build_gpu_swap_bridge.py', 'build_software_refresh.py', 'build_display_frontend.py',
                     'check_gpu_handoff.py', 'check_gmu_firmware.py', 'build_gpu_candidate.py', 'check_gpu_link.py', 'build_display_service.py', 'build_graphics_lifecycle.py', 'build_gop_provider.py', 'build_graphics_late.py',
                     'build_display_kernel.py', 'check_adreno_display_timeline.py', 'build_gpu_graphics_prelink.py', 'build_display_prelink.py', 'check_display_kernel_lifecycle.py', 'check_gop_provider_kernel.py', 'build_display_payload.py',
                     'build_metal_bridge.py', 'build_turnip_ios16.py', 'build_metal_plugin.py', 'check_gpu_userspace.py',
                     'check_metal_translation.py', 'check_a830_shader_compiler.py']
        for name in commands:
            print('Running:', name, flush=True)
            python = ROOT / ('.venv-gpu/bin/python' if name in ('check_display_interface_emulation.py', 'check_ios16_swap.py',
                                                             'prepare_ios16_surface.py', 'prepare_ios16_swap_completion.py', 'prepare_ios16_refresh.py', 'prepare_ios16_request_fields.py', 'prepare_ios16_producer.py', 'prepare_ios16_display_lifecycle.py',
                                                             'prepare_ios16_display_userland.py', 'build_display_frontend.py', 'build_display_service.py', 'audit_ios16_backend_contracts.py', 'check_iphone_legacy_subclass.py', 'check_gpu_link.py', 'check_adreno_display_timeline.py', 'check_display_kernel_lifecycle.py', 'check_gop_provider_kernel.py') else '.venv-uefi/bin/python')
            subprocess.run([python, ROOT / 'scripts' / name], check=True)
    names = ['a830-backend', 'a830-backend-tests', 'ios16-graphics-abi', 'ios16-display-abi', 'ios16-display-interface',
             'ios16-display-emulation', 'ios16-display-subclass', 'ios16-display-lifecycle', 'ios16-display-swap', 'ios16-swap-completion', 'ios16-refresh-interface', 'ios16-request-fields', 'ios16-producer',
             'ios16-display-cache', 'ios16-display-userland', 'ios16-display-frontend', 'ios16-display-service', 'ios16-backend-discovery', 'ios16-software-refresh', 'ios16-surface-interface', 'ios16-surface-backing', 'ios16-diagnostic-console', 'ios16-gpu-swap-bridge', 'gpu-firmware',
             'gpu-policy', 'gpu-board-candidate', 'gpu-handoff-tests', 'gmu-firmware-tests', 'gpu-kernel-candidate', 'gpu-link-probe', 'adreno-display-timeline', 'gpu-graphics-prelink',
             'metal-rust-bridge', 'turnip-ios16', 'metal-plugin', 'gpu-userspace', 'metal-translation-tests', 'a830-shader-compiler',
             'ios16-graphics-lifecycle','ios16-gop-provider','ios16-graphics-late','ios16-display-kernel','ios16-display-prelink','ios16-display-kernel-lifecycle','ios16-gop-provider-kernel','ios16-display-payload']
    reports = {name: json.loads((ROOT / 'reports' / (name + '.json')).read_text()) for name in names}
    identities = {}
    for name, report in reports.items():
        require('PASS' in report['result'], 'GPU stage has no passing result: ' + name)
        for field in ('archive', 'library'):
            if field in report:
                path = ROOT / report[field]
                require(sha(path) == report[field + '_sha256'], 'GPU artifact changed after validation: ' + str(path))
                identities[str(path.relative_to(ROOT))] = report[field + '_sha256']
    backend, candidate = reports['a830-backend'], reports['gpu-kernel-candidate']
    require(backend['native_kernel_sha256'] == candidate['native_kernel_sha256'] == sha(NATIVE),
            'GPU kernel objects were checked against an older kernel')
    require(backend['builder_sha256']==sha(ROOT/'scripts/build_a830_backend.py') and
            reports['a830-backend-tests']['builder_sha256']==sha(ROOT/'scripts/check_a830_backend.py'),
            'Native backend or sanitized test orchestrator changed since validation')
    bridge, turnip, plugin = reports['metal-rust-bridge'], reports['turnip-ios16'], reports['metal-plugin']
    require(plugin['linked'] and plugin['rust_bridge_sha256'] == bridge['archive_sha256'] and
            plugin['turnip_sha256'] == turnip['library_sha256'], 'Frontend does not use the current bridge/Turnip')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    backend_overlay = backend['optional_call_overlay']
    presenter_overlay = reports['gpu-board-candidate']['optional_call_overlay']
    require(backend_overlay == reports['a830-backend-tests']['optional_call_overlay'] and
            presenter_overlay == reports['gpu-handoff-tests']['optional_call_overlay'] and
            backend_overlay['patch'] == lock['dodge_optional_call_overlays']['backend'] and
            presenter_overlay['patch'] == lock['dodge_optional_call_overlays']['presenter'] and
            reports['gpu-board-candidate']['board_patch'] == lock['dodge_gpu_board_patch'],
            'Native backend/presenter and sanitized tests used different optional-call/board overlays')
    for overlay in (backend_overlay, presenter_overlay):
        require(sha(ROOT / overlay['patch']['path']) == overlay['patch']['sha256'] and
                sha(ROOT / 'drivers/DodgeDisplay/DodgeOptionalCalls.h') == overlay['helper_sha256'],
                'Optional call patch/helper changed')
        for name, digest in overlay['patched_source_sha256'].items():
            require(sha(ROOT / overlay['stage'] / name) == digest, 'Staged optional call source changed')
    timeline_overlay=backend['display_timeline_overlay'];timeline_pin=lock['dodge_adreno_display_timeline']
    require(timeline_overlay==reports['a830-backend-tests']['display_timeline_overlay'] and timeline_overlay['patch']==timeline_pin and
            sha(ROOT/timeline_pin['path'])==timeline_pin['sha256'] and sha(ROOT/timeline_pin['header'])==timeline_pin['header_sha256'] and
            timeline_overlay['stager_sha256']==sha(ROOT/'scripts/adreno_display_timeline.py') and
            timeline_overlay['base_publish_sha256']==backend_overlay['patched_source_sha256']['NativeAdrenoPublish.cpp'],
            'Native backend and host suites use different coherent display snapshot overlays')
    for name,digest in timeline_overlay['patched_source_sha256'].items():
        require(sha(ROOT/timeline_overlay['stage']/name)==digest,'Staged display snapshot source changed: '+name)
    for field in ('source_sha256','header_sha256'):
        for path,digest in backend[field].items():require(sha(ROOT/path)==digest,'Actual compiled backend source changed: '+path)
    require(bridge['cargo_lock_sha256'] == lock['metal_bridge_dependencies']['sha256'] ==
            sha(ROOT / lock['metal_bridge_dependencies']['path']), 'Rust dependency snapshot differs')
    translation = reports['metal-translation-tests']
    require(translation['translator_revision'] == bridge['translator_revision'] == lock['metal2vulkan_reference']['revision'] and
            translation['runtime_patches'] == bridge['runtime_patches'] == lock['metal_runtime_patches'] and
            translation['translator_source_tree'] == bridge['translator_source_tree'],
            'Offline translator and iOS bridge use different patched sources')
    require(translation['cargo_lock_sha256'] == lock['metal_translation_dependencies']['sha256'] ==
            sha(ROOT / lock['metal_translation_dependencies']['path']), 'Offline translator dependency snapshot differs')
    require(translation['consumer_api_patch'] == lock['metal_translation_consumer_patch'] and
            sha(ROOT / translation['consumer_api_patch']['path']) == translation['consumer_api_patch']['sha256'],
            'Offline translator consumer API patch differs')
    for field in ('host_binary', 'profile'):
        require(sha(ROOT / translation[field]) == translation[field + '_sha256'], 'Offline translator artifact changed: ' + field)
        identities[translation[field]] = translation[field + '_sha256']
    for artifact in translation['spirv_modules']:
        require(sha(ROOT / artifact['path']) == artifact['sha256'], 'Validated shader module changed: ' + artifact['path'])
        identities[artifact['path']] = artifact['sha256']
    for path, digest in translation['air_source_sha256'].items():
        require(sha(ROOT / path) == digest, 'Offline translator AIR input changed: ' + path)
    require(translation['base_profile_sha256'] == sha(ROOT / '.cache/gpu-work/metal2vulkan/crates/metal2vulkan-validation/profiles/vk12-floor.json') and
            translation['turnip_feature_source_sha256'] == sha(ROOT / '.cache/gpu-work/mesa/src/freedreno/vulkan/tu_device.cc'),
            'Offline capability profile no longer matches production compiler sources')
    ir3 = reports['a830-shader-compiler']
    require(ir3['mesa_revision'] == turnip['mesa_revision'] and ir3['production_source_id'] == turnip['source_id'] and
            ir3['production_mesa_patches'] == turnip['patches'] == lock['mesa_runtime_patches'] and
            ir3['source_sha256'] == sha(ROOT / 'tools/A830CompilerProbe.c'), 'A830 code-generator probe uses different sources')
    require(sha(ROOT / ir3['host_binary']) == ir3['host_binary_sha256'], 'Actual A830 compiler probe changed')
    identities[ir3['host_binary']] = ir3['host_binary_sha256']
    for item in ir3['cases'] + ir3['translated_spirv_cases']:
        for field in ('binary', 'disassembly'):
            require(sha(ROOT / item[field]) == item[field + '_sha256'], 'A830 machine code/disassembly changed after reassembly comparison')
            identities[item[field]] = item[field + '_sha256']
        if 'input_spirv' in item:
            require(sha(ROOT / item['input_spirv']) == item['input_sha256'], 'A830 compiler used an older AIR-derived SPIR-V input')
    require(sha(ROOT / lock['gpu_python_requirements']['path']) == lock['gpu_python_requirements']['sha256'],
            'GPU Python dependency lock changed')
    require(turnip['abi_header_sha256'] == sha(ROOT / lock['a830_backend_reference']['path'] / 'NativeAdrenoABI.h'),
            'Kernel and Turnip wire ABI headers differ')
    firmware = reports['gpu-firmware']
    require(firmware['pin_sha256'] == lock['oneplus13_gpu_firmware']['sha256'] ==
            sha(ROOT / lock['oneplus13_gpu_firmware']['path']), 'Target firmware provenance/pins differ')
    require(reports['gpu-policy']['captured_dtb_sha256'] == reports['gpu-board-candidate']['captured_dtb_sha256'],
            'Board connection and power policy use different captures')
    require(reports['gpu-handoff-tests']['target_board_source_sha256'] == reports['gpu-board-candidate']['board_source_sha256'],
            'Board handoff test uses an older board source')
    board=reports['gpu-board-candidate'];metal_registration=board['metal_registration_host_tests']
    require(board['metal_registration_builder_sha256']==sha(ROOT/'scripts/check_gpu_metal_host.py') and
            board['metal_registration_init_property_attach_failure_releases_service'] and
            metal_registration['result']=='PASS' and metal_registration['case_count']==len(metal_registration['cases'])==15 and
            all(c['result']=='PASS' for c in metal_registration['cases']) and
            metal_registration['actual_staged_board_source_sha256']==board['board_source_sha256'] and
            metal_registration['loader_metadata_accelerator_and_registry_are_peers'] and not metal_registration['real_iokit_or_gpu_execution'],
            'Board Metal registration cleanup checks are stale or overstate runtime execution')
    for path,digest in metal_registration['source_sha256'].items():require(sha(ROOT/path)==digest,'Metal registration host source changed: '+path)
    for field in ('host_binary','snippet'):
        require(sha(ROOT/metal_registration[field])==metal_registration[field+'_sha256'],'Metal registration artifact changed: '+field)
        identities[metal_registration[field]]=metal_registration[field+'_sha256']
    startup=metal_registration['startup_tests']
    require(startup['result']=='PASS' and startup['case_count']==len(startup['cases'])==6 and startup['concurrent_callers']==16 and
            startup['hardware_and_logging_are_peers'] and all(c['result']=='PASS' for c in startup['cases']),
            'Board atomic startup gate lacks its direct entry concurrency/failure checks')
    for field in ('host_binary','snippet'):
        require(sha(ROOT/startup[field])==startup[field+'_sha256'],'Board startup test artifact changed: '+field)
        identities[startup[field]]=startup[field+'_sha256']
    require(reports['ios16-graphics-abi']['identity']['original_sha256'] ==
            reports['ios16-display-abi']['original_kernelcache_sha256'], 'Graphics family audits use different iPhone inputs')
    interface,emulation=reports['ios16-display-interface'],reports['ios16-display-emulation']
    require(sha(ROOT / 'build/ios16-display-interface/dispatch.o') == interface['native_probe_object_sha256'] == emulation['native_probe_sha256'] and
            interface['builder_sha256']==sha(ROOT/'scripts/prepare_ios16_display_interface.py') and
            interface['contract_sha256']==lock['iphone_display_interface']['sha256']==sha(ROOT/interface['contract']) and
            interface['header_sha256']==lock['iphone_display_interface']['header_sha256']==sha(ROOT/interface['header']) and
            interface['qualified_virtual_dispatch_slots']==emulation['qualified_virtual_dispatch_slots']==[178,211,212,242,246,274,276,281,282,292,293,321,322,329] and
            interface['unclassified_backend_argument_slots']==[243] and
            interface['backend_contract_sha256']==emulation['backend_contract_sha256']==lock['iphone_backend_discovery']['sha256'] and
            emulation['backend_emulator_sha256']==sha(ROOT/'scripts/audit_ios16_backend_contracts.py') and
            emulation['total_case_count']==len(emulation['cases'])+len(emulation['backend_cases'])==45 and
            emulation['stock_controller_is_peer'] and emulation['stock_report_helpers_are_peers'] and
            not emulation['original_full_report_or_controller_implementation_executed'] and
            emulation['interface_contract_sha256']==interface['contract_sha256'] and
            emulation['interface_report_sha256']==sha(ROOT/'reports/ios16-display-interface.json') and
            emulation['builder_sha256']==sha(ROOT/'scripts/check_display_interface_emulation.py') and
            not interface['object_instantiated'] and not emulation['real_iokit_instance_constructed'],
            'Display CPU-model test used older source/contracts/native dispatch or overstates object construction')
    subclass=reports['ios16-display-subclass']
    require(subclass['builder_sha256']==sha(ROOT/'scripts/check_iphone_legacy_subclass.py') and
            subclass['emulator_sha256']==sha(ROOT/'scripts/ios16_subclass_emulation.py') and
            subclass['interface_report_sha256']==sha(ROOT/'reports/ios16-display-interface.json') and
            subclass['interface_contract_sha256']==interface['contract_sha256'] and
            subclass['native_kernel_sha256']==sha(NATIVE) and subclass['original_kernelcache_sha256']==reports['ios16-display-abi']['original_kernelcache_sha256'] and
            subclass['legacy_base_bytes']==subclass['marker_offset']==5728 and subclass['fixture_instance_bytes']==5736 and
            subclass['native_vtable_entries']==subclass['strict_link_pointer_readbacks']==338 and
            subclass['original_binding_count']==len(subclass['original_bindings'])==171 and
            subclass['original_code_binding_count']==170 and subclass['original_metaclass_binding_count']==1 and
            subclass['native_inherited_slots']==155 and subclass['original_inherited_slots']==168 and
            subclass['own_override_slots']==[0,1,178,211,212,242,243,274,276,282,292,293,321,322,329] and
            subclass['case_count']==len(subclass['arm64_cases'])==7 and
            [c['result'] for c in subclass['arm64_cases']]==['PASS']*6+['REJECTED'] and
            subclass['original_parent_ctor_dtor_code_executed'] and subclass['source_parent_ctor_dtor_code_executed'] and
            not subclass['parent_lifetime_uses_peers'] and
            all(not c['parent_uses_software_peers'] and c['retain_count_initialized_to_one'] and
                c['destructor_vptr_poison_preserved'] and c['full_object_bytes_match_original_parent'] and
                c['original_parent_metaclass_address_checked'] for c in subclass['arm64_cases'][:6]) and
            subclass['inherited_pointer_corruption_control']=='REJECTED' and subclass['strict_no_undefined'] and
            subclass['slot243_fixture_traps_without_claiming_prototype'] and
            not any(subclass[k] for k in ('binding_object_has_code_or_data',
                'original_metaclass_registered','original_iokit_instance_constructed','real_display_provider_installed',
                'kernel_candidate_includes_fixture','default_kernel_selected','hardware_tested')),
            'Native derived vtable/lifetime/binding evidence changed or overstates an operational display provider')
    for path,digest in subclass['source_sha256'].items():require(sha(ROOT/path)==digest,'Native derived class source/header changed: '+path)
    for field in ('binding_object','native_probe','linked_fixture','link_manifest','compile_manifest'):
        require(sha(ROOT/subclass[field])==subclass[field+'_sha256'],'Native derived class artifact changed: '+field)
        identities[subclass[field]]=subclass[field+'_sha256']
    subclass_bindings={s['name']:hex(s['value']) for s in symbols((ROOT/subclass['binding_object']).read_bytes()) if s['kind']==3}
    require(subclass_bindings==subclass['original_bindings'] and
            not any('IPhoneLegacySubclassProbe' in name or 'original-subclass-bindings' in name for name in candidate['object_sha256']),
            'Native derived class absolute alias readback changed or the test fixture entered the real candidate')
    lifecycle=reports['ios16-display-lifecycle']
    require(lifecycle['builder_sha256']==sha(ROOT/'scripts/prepare_ios16_display_lifecycle.py') and lifecycle['native_kernel_sha256']==sha(NATIVE) and
            lifecycle['contract_sha256']==lock['iphone_display_lifecycle']['sha256']==sha(ROOT/lifecycle['contract']) and
            lifecycle['header_sha256']==lock['iphone_display_lifecycle']['header_sha256']==sha(ROOT/lifecycle['header']) and
            lifecycle['original_kernelcache_sha256']==reports['ios16-display-abi']['original_kernelcache_sha256'] and
            lifecycle['case_count']==len(lifecycle['cases'])==29 and lifecycle['startup_guard_read_only'] and lifecycle['registration_precedes_start_return'] and
            not any(lifecycle[k] for k in ('original_init_and_queue_bytes_changed','original_factory_or_event_loop_implementation_executed',
                'original_full_start_stop_executed','initialization_failure_ownership_qualified','concrete_legacy_subclass_installed','hardware_tested')),
            'Original lifecycle/native startup shape evidence changed or overstates actual IOKit execution')
    for path,digest in lifecycle['source_sha256'].items():require(sha(ROOT/path)==digest,'Original lifecycle checker/header source changed: '+path)
    require(sha(ROOT/lifecycle['native_probe'])==lifecycle['native_probe_sha256'],'Native startup shape/loop dispatch probe changed')
    identities[lifecycle['native_probe']]=lifecycle['native_probe_sha256']
    swap = reports['ios16-display-swap']
    require(swap['original_kernelcache_sha256'] == reports['ios16-display-abi']['original_kernelcache_sha256'] and
            swap['contract_sha256'] == lock['iphone_display_swap']['sha256'] == sha(ROOT / swap['contract']) and
            swap['header_sha256'] == lock['iphone_display_swap']['header_sha256'] == sha(ROOT / swap['header']),
            'Display queue access differs from the current exact iPhone interface')
    require(sha(ROOT / swap['native_object']) == swap['native_object_sha256'], 'Native display queue code changed after original-block comparison')
    identities[swap['native_object']] = swap['native_object_sha256']
    completion = reports['ios16-swap-completion']
    require(completion['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            completion['native_kernel_sha256'] == sha(NATIVE) and
            completion['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_swap_completion.py') and
            completion['body_emulator_sha256']==sha(ROOT/'scripts/ios16_completion_emulation.py') and
            completion['bounded_body_case_count']==len(completion['arm64_body_cases'])==16 and
            completion['full_body_paths_executed']==sum(c['unchanged_full_body_executed'] for c in completion['arm64_body_cases'])==13 and
            completion['tail_paths_executed']==sum(c['original_tail_executed'] for c in completion['arm64_body_cases'])==12 and
            all(c['result']=='PASS' for c in completion['arm64_body_cases']) and
            completion['original_completion_body_executed'] and completion['original_notification_and_mode_helpers_executed'] and
            completion['original_release_clear_wakeup_instructions_executed'] and
            completion['original_request_release_and_gate_are_peers'] and completion['original_surface_commit_is_peer'] and
            not any(completion[k] for k in ('actual_original_retirement_lifetime_qualified','actual_request_refcount_operations_executed',
                'request_released','gate_wakeup_executed','fence_signalled','hardware_tested')) and
            completion['contract_sha256'] == lock['iphone_display_completion']['sha256'] == sha(ROOT / completion['contract']) and
            completion['header_sha256'] == lock['iphone_display_completion']['header_sha256'] == sha(ROOT / completion['header']),
            'Original swap completion binding differs from the current exact iPhone interface')
    require(completion['queue_header_sha256'] == swap['header_sha256'] and swap['read_only_eligibility_cases'] == 13,
            'Completion eligibility used an older queue header')
    require(sha(ROOT / completion['native_probe']) == completion['native_probe_sha256'], 'Completion native call probe changed')
    identities[completion['native_probe']] = completion['native_probe_sha256']
    fields = reports['ios16-request-fields']
    require(fields['native_kernel_sha256'] == sha(NATIVE) and
            fields['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            fields['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_request_fields.py') and
            fields['contract_sha256'] == lock['iphone_request_fields']['sha256'] == sha(ROOT / fields['contract']) and
            fields['header_sha256'] == lock['iphone_request_fields']['header_sha256'] == sha(ROOT / fields['header']) and
            fields['queue_header_sha256'] == swap['header_sha256'] and not fields['snapshot_validation_semantics_complete'],
            'Read-only request fields differ from current exact iPhone builders or claim unsupported validation')
    require(sha(ROOT / fields['native_probe']) == fields['native_probe_sha256'], 'Read-only request snapshot probe changed')
    identities[fields['native_probe']] = fields['native_probe_sha256']
    producer = reports['ios16-producer']
    require(producer['native_kernel_sha256'] == sha(NATIVE) and producer['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            producer['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_producer.py') and
            producer['contract_sha256'] == lock['iphone_display_producer']['sha256'] == sha(ROOT / producer['contract']) and
            producer['header_sha256'] == lock['iphone_display_producer']['header_sha256'] == sha(ROOT / producer['header']) and
            producer['queue_header_sha256'] == swap['header_sha256'] and not producer['original_iosurface_fence_implementation_executed'],
            'Exact iPhone producer registration/callback/native-guard evidence changed')
    require(sha(ROOT / producer['native_probe']) == producer['native_probe_sha256'], 'Native producer readiness guard changed')
    identities[producer['native_probe']] = producer['native_probe_sha256']
    cache = reports['ios16-display-cache']
    require(cache['product'] == 'iPhone10,3' and cache['build'] == '20H392' and
            cache['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_display_cache.py') and
            cache['extractor_source_sha256'] == sha(ROOT / 'tools/ApfsExtract.cpp') and
            cache['reader_source'] == lock['apfs_readonly_reference'] and cache['cache_format'] == lock['apple_dyld_cache_format'] and
            cache['compression_headers'] == lock['apfs_host_bzip2_headers'] and
            file_sha(ROOT / cache['source_image']) == cache['source_image_sha256'] and
            file_sha(ROOT / cache['extractor']) == cache['extractor_sha256'] and
            not cache['filesystem_mounted'] and not cache['block_devices_opened'] and not cache['cache_bytes_modified'],
            'Original display cache extraction used older or non-regular-image inputs')
    for spec in (cache['cache_format'], cache['compression_headers']):
        require(file_sha(ROOT / spec['path']) == spec['sha256'], 'Display cache host input changed')
    for item in cache['cache_files']:
        require(file_sha(ROOT / item['path']) == item['sha256'] and item['changed_4k_piece_controls'], 'Original display cache integrity evidence changed')
        identities[item['path']] = item['sha256']
    userland = reports['ios16-display-userland']
    require(userland['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_display_userland.py') and
            userland['cache_reader_sha256'] == sha(ROOT / 'scripts/ios16_display_cache.py') and
            userland['contract_sha256'] == lock['iphone_display_userland']['sha256'] == sha(ROOT / userland['contract']) and
            userland['cache_report_sha256'] == sha(ROOT / 'reports/ios16-display-cache.json') and
            userland['original_kernelcache_sha256']==swap['original_kernelcache_sha256'] and userland['original_size_kernel_functions_executed']==3 and
            userland['original_kernel_size_scalar_to_double_dataflow_checked'] and not userland['display_size_callback_is_peer'] and
            not userland['full_userspace_or_dyld_executed'], 'Original iPhone display packet setter evidence changed')
    discovery = reports['ios16-backend-discovery']
    require(discovery['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            discovery['builder_sha256'] == sha(ROOT / 'scripts/audit_ios16_backend_contracts.py') and
            discovery['contract_sha256'] == lock['iphone_backend_discovery']['sha256'] == sha(ROOT / discovery['contract']) and
            not discovery['full_backend_override_prototypes_qualified'] and not discovery['stock_subclass_selected'],
            'Stock backend discovery differs from exact iPhone evidence or is incorrectly selected')
    surface = reports['ios16-surface-interface']
    require(surface['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            surface['contract_sha256'] == lock['iphone_surface_interface']['sha256'] == sha(ROOT / surface['contract']) and
            surface['header_sha256'] == lock['iphone_surface_interface']['header_sha256'] == sha(ROOT / surface['header']),
            'Original IOSurface bindings differ from the current exact iPhone interface')
    require(sha(ROOT / surface['native_probe']) == surface['native_probe_sha256'], 'Typed IOSurface native probe changed')
    identities[surface['native_probe']] = surface['native_probe_sha256']
    backing = reports['ios16-surface-backing']
    require(backing['native_kernel_sha256'] == sha(NATIVE) and
            backing['surface_contract_sha256'] == surface['contract_sha256'] and
            backing['surface_bindings_archive_sha256'] == surface['archive_sha256'],
            'Surface backing archive uses older native/IOSurface inputs')
    for path, digest in backing['source_sha256'].items():
        require(sha(ROOT / path) == digest, 'Surface backing source changed after native/sanitized checks: ' + path)
    console = reports['ios16-diagnostic-console']
    require(console['patch'] == lock['dodge_diagnostic_console_patch'] and
            sha(ROOT / console['patch']['path']) == console['patch']['sha256'] and
            console['source_revision'] == lock['pagani_reference']['revision'] and
            sha(ROOT / 'drivers/DodgeDisplay/DodgeDiagnosticConsole.cpp') == console['adapter_sha256'] and
            sha(ROOT / 'tests/DodgeConsoleBindTest.c') == console['bind_test_sha256'] and
            console['native_kernel_sha256'] == sha(NATIVE) and
            sha(ROOT / 'scripts/build_diagnostic_console.py') == console['builder_sha256'] and
            candidate['diagnostic_console_report_sha256'] == sha(ROOT / 'reports/ios16-diagnostic-console.json'),
            'Diagnostic console differs from the tested current native candidate')
    require(sha(ROOT / 'build/ios16-diagnostic-console/source/BootProgress.c') == console['source_sha256'] and
            sha(ROOT / 'tests/DodgeDiagnosticConsoleTest.cpp') == console['provider_test_sha256'],
            'Console renderer or provider ownership test changed')
    for path, digest in console['software_peer_headers'].items():
        require(sha(ROOT / path) == digest, 'Console software ownership peer changed')
    for item in console['objects']:
        require(sha(ROOT / item['path']) == item['sha256'], 'Diagnostic console object changed')
    swap_bridge = reports['ios16-gpu-swap-bridge']
    require(swap_bridge['native_kernel_sha256'] == sha(NATIVE) and
            swap_bridge['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            swap_bridge['builder_sha256'] == sha(ROOT / 'scripts/build_gpu_swap_bridge.py') and
            swap_bridge['queue_report_sha256'] == sha(ROOT / 'reports/ios16-display-swap.json') and
            swap_bridge['completion_report_sha256'] == sha(ROOT / 'reports/ios16-swap-completion.json') and
            swap_bridge['completion_binding_archive_sha256'] == completion['archive_sha256'] and
            swap_bridge['producer_report_sha256'] == sha(ROOT / 'reports/ios16-producer.json') and
            swap_bridge['original_producer_ready_words_rechecked'] and
            swap_bridge['default_transfer_cpu_copy'] and swap_bridge['cpu_copy_requires_no_presenter'] and
            swap_bridge['experimental_presenter_requires_quiescence_contract'] and
            candidate['gpu_swap_bridge_report_sha256'] == sha(ROOT / 'reports/ios16-gpu-swap-bridge.json'),
            'GPU completion bridge uses older ABI/build/test inputs')
    require(swap_bridge['host_case_count'] == len(swap_bridge['host_tests']['cases']) and
            swap_bridge['host_tests']['result'] == 'PASS' and
            not swap_bridge['host_tests']['original_completion_executed'], 'GPU completion test scope changed')
    for path, digest in swap_bridge['source_sha256'].items():
        require(sha(ROOT / path) == digest, 'GPU completion bridge or software peer source changed: ' + path)
    for item in swap_bridge['objects']:
        require(sha(ROOT / item['path']) == item['sha256'], 'GPU completion bridge object changed')
    refresh_interface = reports['ios16-refresh-interface']
    require(refresh_interface['native_kernel_sha256'] == sha(NATIVE) and
            refresh_interface['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            refresh_interface['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_refresh.py') and
            refresh_interface['contract_sha256'] == lock['iphone_display_refresh']['sha256'] == sha(ROOT / refresh_interface['contract']) and
            refresh_interface['header_sha256'] == lock['iphone_display_refresh']['header_sha256'] == sha(ROOT / refresh_interface['header']) and
            refresh_interface['queue_header_sha256'] == swap['header_sha256'], 'Exact iPhone refresh sender/list interface changed')
    require(sha(ROOT / refresh_interface['native_probe']) == refresh_interface['native_probe_sha256'], 'Native refresh call probe changed')
    identities[refresh_interface['native_probe']] = refresh_interface['native_probe_sha256']
    refresh = reports['ios16-software-refresh']
    require(refresh['native_kernel_sha256'] == sha(NATIVE) and
            refresh['builder_sha256'] == sha(ROOT / 'scripts/build_software_refresh.py') and
            refresh['refresh_interface_report_sha256'] == sha(ROOT / 'reports/ios16-refresh-interface.json') and
            refresh['workloop_audit_report_sha256'] == sha(ROOT / 'reports/ios16-gpu-swap-bridge.json') and
            candidate['software_refresh_report_sha256'] == sha(ROOT / 'reports/ios16-software-refresh.json'),
            'Software refresh uses older exact ABI/work-loop/build inputs')
    require(refresh['host_case_count'] == len(refresh['host_tests']['cases']) and refresh['host_tests']['result'] == 'PASS' and
            refresh['created_disabled'] and not refresh['hardware_vblank_generated'], 'Software refresh test/cadence scope changed')
    for path, digest in {**refresh['source_sha256'], **refresh['actual_kernel_event_source_sha256']}.items():
        require(sha(ROOT / path) == digest, 'Software refresh or actual timer implementation source changed: ' + path)
    for item in refresh['objects']:
        require(sha(ROOT / item['path']) == item['sha256'], 'Software refresh object changed')
    frontend = reports['ios16-display-frontend']
    require(frontend['native_kernel_sha256'] == sha(NATIVE) and frontend['original_kernelcache_sha256'] == swap['original_kernelcache_sha256'] and
            frontend['builder_sha256'] == sha(ROOT / 'scripts/build_display_frontend.py') and
            frontend['contract_sha256'] == lock['iphone_display_frontend']['sha256'] == sha(ROOT / frontend['contract']) and
            frontend['header_sha256'] == lock['iphone_display_frontend']['header_sha256'] == sha(ROOT / frontend['header']) and
            candidate['display_frontend_report_sha256'] == sha(ROOT / 'reports/ios16-display-frontend.json') and
            candidate['surface_backing_report_sha256'] == sha(ROOT / 'reports/ios16-surface-backing.json') and
            frontend['host_tests']['result'] == 'PASS' and frontend['host_case_count'] == len(frontend['host_tests']['cases']) and
            frontend['host_tests']['noncanonical_byte_mutations'] == 1124 and frontend['native_guard_tests']['cases'] and
            frontend['adreno_first_successful_target_preserved'] and frontend['adreno_query_failure_holds_frame'] and
            frontend['adreno_observed_timeline_regression_latches_refusal'] and
            frontend['dequeued_requests_reconciled_after_bounded_queue_audit'] and frontend['ledger_entry_detached_before_virtual_releases'] and
            frontend['original_display_mode_matches_gop_and_rechecked'] and
            frontend['original_all_startup_queues_empty_required'] and
            frontend['creation_enters_workloop_with_retained_inputs'] and frontend['creation_rechecks_loop_and_gate_identity'] and
            frontend['producer_retry_uses_gated_iotimer'] and frontend['producer_retry_nanoseconds'] == 200000 and
            frontend['producer_timeout_never_retires'] and frontend['cpu_producer_mode_explicit'] and
            frontend['default_transfer_cpu_copy'] and frontend['default_adreno_producer_wait'] and frontend['experimental_presenter_explicit'] and
            frontend['software_refresh_connected'] and frontend['software_refresh_initially_disabled'] and
            frontend['software_refresh_stopped_before_owner_release'] and candidate['software_refresh_bounded_frontend_connected'] and
            frontend['adreno_first_recovery_epoch_preserved'] and frontend['adreno_epoch_change_latches_refusal'] and frontend['adreno_snapshot_nonblocking'] and
            '_dodge_adreno_display_timeline' in frontend['imports']['required_board_or_original_imports'] and
            '_dodge_adreno_display_timeline' in backend['imports']['defined'] and not frontend['adreno_timeline_epoch_or_fault_recovery_qualified'] and
            not frontend['concrete_legacy_subclass_installed'] and not frontend['original_request_builder_body_executed'],
            'Bounded source frontend uses older exact inputs or overstates original lifecycle/provider qualification')
    for path, digest in frontend['source_sha256'].items():
        require(sha(ROOT / path) == digest, 'Bounded frontend/test source changed: ' + path)
    for name, digest in frontend['dependency_report_sha256'].items():
        require(sha(ROOT / 'reports' / (name + '.json')) == digest, 'Bounded frontend dependency changed: ' + name)
    for item in frontend['objects']:
        require(sha(ROOT / item['path']) == item['sha256'], 'Bounded frontend native object changed')
    require(sha(ROOT / frontend['native_probe']) == frontend['native_probe_sha256'], 'Bounded frontend native guard probe changed')
    identities[frontend['native_probe']] = frontend['native_probe_sha256']
    link = reports['gpu-link-probe']
    require(link['native_kernel_sha256'] == sha(NATIVE) and link['builder_sha256'] == sha(ROOT / 'scripts/check_gpu_link.py') and
            link['candidate_report_sha256'] == sha(ROOT / 'reports/gpu-kernel-candidate.json') and
            link['candidate_archive_sha256'] == candidate['archive_sha256'] and
            link['default_kernel_unchanged'] and link['strict_no_undefined'] and not link['absence_adapter_contains_code_or_data'],
            'Isolated native link proof uses older or fabricated provider inputs')
    for field in ('partial_object', 'isolated_kernel', 'baseline_replay', 'input_manifest', 'command_manifest'):
        require(sha(ROOT / link[field]) == link[field + '_sha256'], 'Isolated link proof artifact changed: ' + field)
        identities[link[field]] = link[field + '_sha256']
    for path, digest in json.loads((ROOT / link['input_manifest']).read_text()).items():
        require(sha(ROOT / path) == digest, 'Isolated native link input changed: ' + path)
    probe = link['optional_call_arm64_probe']
    require(sha(ROOT / probe['native_probe']) == probe['native_probe_sha256'], 'Optional weak-call ARM64 probe changed')
    identities[probe['native_probe']] = probe['native_probe_sha256']
    timeline=reports['adreno-display-timeline']
    require(timeline['builder_sha256']==sha(ROOT/'scripts/check_adreno_display_timeline.py') and
            timeline['backend_report_sha256']==sha(ROOT/'reports/a830-backend.json') and
            timeline['link_report_sha256']==sha(ROOT/'reports/gpu-link-probe.json') and timeline['native_kernel_sha256']==link['isolated_kernel_sha256'] and
            timeline['timeline_overlay']==timeline_overlay and timeline['case_count']==len(timeline['cases'])==22 and
            all(case['result']=='PASS' for case in timeline['cases']) and timeline['failure_preserves_output'] and
            timeline['publisher_recovery_advances_saturating_epoch'] and timeline['multi_ring_preemption_refused'] and
            not any(timeline[k] for k in ('native_instruction_bytes_changed','actual_cache_or_mmio_executed','original_iokit_mutex_executed',
                'reset_hardware_qualified','external_reset_paths_qualified','hardware_tested')),
            'Native coherent snapshot evidence uses stale inputs or overstates hardware execution')
    for path,digest in timeline['source_sha256'].items():require(sha(ROOT/path)==digest,'Native snapshot probe source changed: '+path)
    layout=timeline['native_layout_probe']
    require(layout['production_instruction_bytes_equal'] and
            sha(ROOT/'build/cph2653-a830-backend/compile-commands.json')==layout['compile_record_sha256'] and
            sha(ROOT/'build/cph2653-a830-backend/NativeAdrenoPublish.o')==layout['production_object_sha256'],
            'Native snapshot layout probe no longer matches actual production compilation')
    for field in ('object','compiler_layout_log'):
        require(sha(ROOT/layout[field])==layout[field+'_sha256'],'Native snapshot layout artifact changed: '+field)
        identities[layout[field]]=layout[field+'_sha256']
    graphics=reports['gpu-graphics-prelink']
    require(graphics['builder_sha256']==sha(ROOT/'scripts/build_gpu_graphics_prelink.py') and
            graphics['profile_sha256']==lock['iphone_gpu_prelink_profile']['sha256']==sha(ROOT/graphics['profile']) and
            graphics['link_report_sha256']==sha(ROOT/'reports/gpu-link-probe.json') and
            graphics['isolated_native_input_sha256']==link['isolated_kernel_sha256'] and
            graphics['original_kernelcache_sha256']==swap['original_kernelcache_sha256'] and
            graphics['pointer_sites_read_back']==sum(graphics['pointer_counts'].values())==58962 and
            len(graphics['components'])==len(graphics['original_executable_segments'])==27 and len(graphics['kernel_interfaces'])==7 and
            len(graphics['original_aliases'])==20 and graphics['early_security_entries_read_back']==2 and
            graphics['original_executable_bytes_unchanged'] and graphics['native_executable_bytes_unchanged'] and
            graphics['source_crypto_post_field_verified'] and graphics['darwinboot_production_parser']=='PASS' and
            graphics['default_artifacts_unchanged'] and graphics['strict_emission'] and
            not any(graphics[k] for k in ('allow_missing','substitute_addresses','concrete_legacy_display_provider_installed',
                'initializer_lifecycle_qualified','abi_qualified','loadable','runtime_qualified','default_kernel_selected',
                'boot_payload_packaged','hardware_tested','ready_for_ios_boot','source_crypto_runtime_selftests_executed')),
            'Strict isolated original-graphics prelink uses older inputs or overstates initialization/boot qualification')
    controls=graphics['negative_readback_controls']
    require([item['case'] for item in controls]==['pointer','original-code','post-field','native-code','absolute-alias'] and
            all(item['result']=='REJECTED' for item in controls),'Original-graphics prelink lacks all five corrupt readback controls')
    for path,digest in graphics['source_sha256'].items():
        require(sha(ROOT/path)==digest,'Original-graphics prelink source changed: '+path)
    for field in ('sealed_native','candidate','emission_record','post_record','sealed_post_record'):
        require(sha(ROOT/graphics[field])==graphics[field+'_sha256'],'Original-graphics prelink artifact changed: '+field)
        identities[graphics[field]]=graphics[field+'_sha256']
    for path,digest in graphics['protected_default_artifact_sha256'].items():
        require(sha(ROOT/path)==digest,'Default artifact changed since isolated graphics preparation: '+path)
    service=reports['ios16-display-service']
    require(service['builder_sha256']==sha(ROOT/'scripts/build_display_service.py') and
            service['native_kernel_sha256']==sha(NATIVE) and service['gpu_kernel_sha256']==link['isolated_kernel_sha256'] and
            service['original_kernelcache_sha256']==subclass['original_kernelcache_sha256'],
            'Concrete display service uses stale native/original kernels')
    require(service['concrete_source_class_built'] and service['strict_no_undefined'] and
            service['native_vtable_entries']==service['strict_link_pointer_readbacks']==338 and
            service['original_binding_count']==172 and service['native_binding_count']==191 and
            service['original_inherited_slots']==161 and service['native_inherited_slots']==153 and
            service['own_override_slots']==[0,1,7,14,79,84,86,87,109,141,155,178,211,212,242,243,274,276,282,292,293,321,322,329] and
            service['all_abstract_slots_have_source_entries'] and service['slot243_raw_leaf_register_equivalence'] and
            service['vtable_corruption_control']=='REJECTED' and
            service['initializer_removed_from_early_registration'] and service['initializer_staging_preserves_instructions'] and
            service['initializer_requires_original_parent_registration'] and service['initializer_requires_serialized_loader_context'] and
            service['allocation_requires_owned_metaclass_postModLoad_registration'] and
            service['concrete_instance_bytes']==5768 and service['client_creation_uses_gated_admission'] and
            service['detach_deferred_until_drain_and_parent_stop_return'] and service['detached_original_loop_survives_in_controller'] and
            service['partial_parent_failure_cleanup_after_start_return_and_drain'] and service['original_partial_parent_stop_cpu_cases']==11 and
            service['original_qualified_parent_start_and_stop_are_native_ioservice'] and
            not any(service[k] for k in ('slot243_source_call_prototype_qualified','parent_registration_checks_executed_on_kernel',
                'original_parent_full_start_stop_executed','runtime_provider_registered','physical_power_implemented',
                'default_kernel_selected','gpu_candidate_includes_service','hardware_tested')),
            'Concrete source vtable/initializer evidence is incomplete or overstates runtime scope')
    require(service['host_case_count']==len(service['host_tests']['cases'])==60 and service['host_tests']['result']=='PASS' and
            service['host_tests']['frontend_is_peer'] and service['arm64_tests']['case_count']==len(service['arm64_tests']['cases'])==69 and
            all(item['result']=='PASS' for item in service['arm64_tests']['cases']) and
            service['arm64_tests']['native_backend_leaf_cases']==27 and service['arm64_tests']['native_start_glue_cases']==11 and
            service['arm64_tests']['native_metadata_guard_cases']==5 and
            service['arm64_tests']['native_client_admission_cases']==6 and service['arm64_tests']['native_deferred_detach_cases']==7 and
            service['arm64_tests']['actual_native_parent_start_leaf_cases']==1 and service['arm64_tests']['original_partial_stop_body']['case_count']==11 and
            service['arm64_tests']['original_partial_stop_body']['scope_no_original_surface_5056'] and
            not service['arm64_tests']['original_partial_stop_body']['real_iokit_ownership_or_runtime_qualified'] and
            not service['arm64_tests']['original_slot243_instruction_bytes_changed'] and
            not service['arm64_tests']['slot243_original_argument_prototype_assumed'] and
            not service['arm64_tests']['original_start_stop_executed'] and
            service['arm64_tests']['core_and_workloop_and_publication_are_peers'],
            'Concrete source class lacks bounded lifecycle/ARM64 peer checks')
    require(service['integration_case_count']==len(service['integration_tests']['cases'])==10 and
            service['integration_tests']['result']=='PASS' and service['integration_tests']['frontend_bridge_refresh_are_actual_source'] and
            service['integration_tests']['original_builder_completion_and_IOKit_are_peers'] and
            sha(ROOT/'build/ios16-display-service/display-service-integration-host')==service['integration_binary_sha256'],
            'Concrete coordinator and actual frontend/bridge/refresh integration evidence is stale or incomplete')
    for path,digest in service['source_sha256'].items():require(sha(ROOT/path)==digest,'Concrete display service source changed: '+path)
    for name,digest in service['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'Concrete service dependency changed: '+name)
    for item in service['objects']:
        require(sha(ROOT/item['path'])==item['sha256'],'Concrete service object changed: '+item['path'])
        identities[item['path']]=item['sha256']
    for field in ('linked_fixture','compile_manifest','link_manifest'):
        require(sha(ROOT/service[field])==service[field+'_sha256'],'Concrete display artifact changed: '+field)
        identities[service[field]]=service[field+'_sha256']
    require(sha(ROOT/'build/ios16-display-service/display-service-host')==service['host_binary_sha256'] and
            not any('DodgeIPhoneFramebuffer' in name or 'DodgeDisplayService' in name for name in candidate['object_sha256']),
            'Concrete service host binary changed or the experimental module was silently selected')
    life=reports['ios16-graphics-lifecycle'];life_pin=lock['iphone_graphics_module_lifecycle']
    require(life['builder_sha256']==sha(ROOT/'scripts/build_graphics_lifecycle.py') and
            life['service_report_sha256']==sha(ROOT/'reports/ios16-display-service.json') and life['native_kernel_sha256']==sha(NATIVE) and
            life['original_kernelcache_sha256']==subclass['original_kernelcache_sha256'] and
            life['contract_sha256']==life_pin['sha256']==sha(ROOT/life['contract']) and
            life['header_sha256']==life_pin['header_sha256']==sha(ROOT/life['header']) and
            life['loader_order']==['com.apple.iokit.IOSurface','com.apple.iokit.IOGPUFamily','com.apple.iokit.IOMobileGraphicsFamily'] and
            life['original_constructor_entries']==53 and len(life['original_metadata_aliases'])==3 and
            life['host_tests']['case_count']==len(life['host_tests']['cases'])==33 and
            all(c['result']=='PASS' for c in life['host_tests']['cases']) and life['host_tests']['loader_metadata_and_concrete_display_are_peers'] and
            all(life[k] for k in ('uses_real_OSKext_dependency_start_and_CPP_initialization','deferred_userspace_load_disabled',
                'non_surface_personality_matching_disabled','surface_root_personality_matching_requested','surface_root_nonblocking_preflight',
                'surface_root_retained_during_attach','exact_original_provider_hierarchy_required','exact_metaclass_identity_and_size_required','metaclass_unload_pins_held_after_owned_construction',
                'preModLoad_uses_existing_kernel_owner','postModLoad_required_before_allocation','concurrent_and_reentrant_preparation_refused',
                'metadata_phase_failure_latched','explicit_prepare_then_attach','one_display_start_attempt_per_boot','failed_start_uses_concrete_deferred_detach')) and
            not any(life[k] for k in ('early_initializer_present','gpu_hardware_started_by_prepare','original_loader_executed_on_kernel',
                'original_full_start_stop_executed','runtime_provider_registered','default_kernel_selected','hardware_tested','surface_root_runtime_termination_race_qualified')),
            'Original module prepare/attach evidence is stale or overstates runtime execution')
    require(life['explicit_module_gpu_display_boot_coordinator_built'] and life['boot_preflight_before_hardware'] and
            life['boot_retains_provider_and_surface_root'] and life['boot_pre_hardware_failure_retryable'] and
            life['boot_hardware_attempt_and_failure_one_shot'] and not life['boot_entry_invoked_on_kernel'] and
            life['boot_host_tests']['result']=='PASS' and life['boot_host_tests']['case_count']==len(life['boot_host_tests']['cases'])==24 and
            all(c['result']=='PASS' for c in life['boot_host_tests']['cases']) and life['boot_host_tests']['module_gpu_display_and_iokit_are_peers'] and
            not life['boot_host_tests']['real_hardware_started'] and sha(ROOT/life['boot_host_binary'])==life['boot_host_binary_sha256'],
            'Unified graphics boot coordination is stale, incomplete or overstates hardware execution')
    identities[life['boot_host_binary']]=life['boot_host_binary_sha256']
    for path,digest in life['source_sha256'].items():require(sha(ROOT/path)==digest,'Graphics module source changed: '+path)
    for item in life['objects']:
        require(sha(ROOT/item['path'])==item['sha256'],'Graphics module object changed');identities[item['path']]=item['sha256']
    for field in ('compile_manifest','host_binary'):
        require(sha(ROOT/life[field])==life[field+'_sha256'],'Graphics module artifact changed: '+field);identities[life[field]]=life[field+'_sha256']
    gop=reports['ios16-gop-provider'];gop_pin=lock['iphone_gop_provider']
    require(gop['builder_sha256']==sha(ROOT/'scripts/build_gop_provider.py') and gop['native_kernel_sha256']==sha(NATIVE) and
            gop['graphics_lifecycle_report_sha256']==sha(ROOT/'reports/ios16-graphics-lifecycle.json') and
            gop['original_kernelcache_sha256']==life['original_kernelcache_sha256'] and
            gop['contract_sha256']==gop_pin['sha256']==sha(ROOT/gop['contract']) and
            gop['header_sha256']==gop_pin['header_sha256']==sha(ROOT/gop['header']) and
            gop['original_instance_bytes']==216 and len(gop['original_metadata_aliases'])==1 and len(gop['objects'])==2 and
            gop['host_tests']['case_count']==len(gop['host_tests']['cases'])==60 and gop['host_tests']['result']=='PASS' and
            all(c['result']=='PASS' for c in gop['host_tests']['cases']) and gop['host_tests']['iokit_pe_allocation_and_boot_are_peers'] and
            all(gop[k] for k in ('real_original_metaclass_allocator_used','inherited_public_init_used','actual_current_dt_platform_required',
                'pe_console_memory_descriptor_required','device_memory_property_read_back','original_get_resources_fast_path_required',
                'mode_and_resources_rechecked_after_publication','one_nub_published_per_boot','published_nub_and_original_metadata_pinned',
                'unpublished_failures_unwound_and_retryable','explicit_late_provider_to_gpu_display_entry_built')) and
            not any(gop[k] for k in ('private_apple_fields_written','apple_bus_initializer_called','fake_meta_cast_implementation',
                'early_initializer_present','native_entry_invoked','runtime_provider_registered','apple_bus_or_clock_functions_qualified',
                'runtime_qualified','default_kernel_selected','hardware_tested','ready_for_ios_boot')),
            'GOP provider factory is stale, substitutes an original class, or overstates runtime scope')
    for path,digest in gop['source_sha256'].items():require(sha(ROOT/path)==digest,'GOP provider source changed: '+path)
    for item in gop['objects']:
        require(sha(ROOT/item['path'])==item['sha256'],'GOP provider object changed');identities[item['path']]=item['sha256']
    for field in ('compile_manifest','host_binary'):
        require(sha(ROOT/gop[field])==gop[field+'_sha256'],'GOP provider artifact changed: '+field);identities[gop[field]]=gop[field+'_sha256']
    late_boot=reports['ios16-graphics-late'];late_overlay=late_boot['native_object_overlay']
    require(late_boot['builder_sha256']==sha(ROOT/'scripts/build_graphics_late.py') and late_boot['native_kernel_sha256']==sha(NATIVE) and
            late_overlay['patch']==lock['dodge_graphics_late_overlay'] and sha(ROOT/late_overlay['patch']['path'])==late_overlay['patch']['sha256'] and
            late_overlay['stager_sha256']==sha(ROOT/'scripts/graphics_late_overlay.py') and
            late_boot['host_tests']['case_count']==len(late_boot['host_tests']['cases'])==24 and late_boot['host_tests']['result']=='PASS' and
            all(c['result']=='PASS' for c in late_boot['host_tests']['cases']) and late_boot['host_tests']['kernel_thread_boot_and_iokit_are_peers'] and
            late_boot['host_tests']['actual_staged_iobsd_function_extracted'] and late_boot['boot_argument']=='dodge-graphics=1' and
            late_boot['retry_attempts']==200 and late_boot['retry_milliseconds']==10 and
            all(late_boot[k] for k in ('schedule_after_real_iobsd_publication','independent_kernel_thread_required',
                'one_worker_after_successful_queue','thread_start_failure_retryable','pre_hardware_not_ready_or_busy_retry_only',
                'hardware_attempt_never_retried','owned_successful_display_retained')) and
            not any(late_boot[k] for k in ('default_boot_argument_enabled','early_initializer_present','original_native_source_or_object_modified',
                'native_hook_executed_on_kernel','runtime_qualified','default_kernel_selected','hardware_tested','ready_for_ios_boot')),
            'IOBSD late scheduling overlay is stale, unbounded, enabled by default, or overstates runtime execution')
    for path,digest in late_boot['source_sha256'].items():require(sha(ROOT/path)==digest,'Late boot source changed: '+path)
    for item in late_boot['objects']:
        require(sha(ROOT/item['path'])==item['sha256'],'Late boot object changed');identities[item['path']]=item['sha256']
    for field in ('compile_manifest','host_binary','hook_extracted'):
        require(sha(ROOT/late_boot[field])==late_boot[field+'_sha256'],'Late boot artifact changed: '+field);identities[late_boot[field]]=late_boot[field+'_sha256']
    for field in ('original_object','replacement_object','compile_manifest','patched_source','base_source'):
        require(sha(ROOT/late_overlay[field])==late_overlay[field+'_sha256'],'IOBSD native overlay input/output changed: '+field)
        identities[late_overlay[field]]=late_overlay[field+'_sha256']
    display_kernel=reports['ios16-display-kernel']
    require(display_kernel['builder_sha256']==sha(ROOT/'scripts/build_display_kernel.py') and display_kernel['native_kernel_sha256']==sha(NATIVE) and
            display_kernel['linked_source_objects']==len(display_kernel['objects'])==64 and display_kernel['original_binding_count']==196 and
            display_kernel['strict_no_undefined'] and display_kernel['strong_missing_import_control']=='REJECTED' and
            display_kernel['concrete_initializer_removed_from_early_table'] and display_kernel['actual_early_constructor_count']==99 and
            display_kernel['concrete_class_and_module_entry_linked'] and display_kernel['default_artifacts_unchanged'] and
            len(display_kernel['firmware_readback'])==4 and len(display_kernel['real_linked_entry_points'])==42 and
            display_kernel['native_object_overlay']==late_overlay and display_kernel['opt_in_iobsd_graphics_hook_linked'] and
            display_kernel['default_iobsd_source_object_and_filelist_unchanged'] and
            not any(display_kernel[k] for k in ('absence_adapter_contains_code_or_data','original_components_embedded','runtime_entry_invoked',
                'default_kernel_selected','boot_payload_packaged','initializer_lifecycle_qualified','hardware_tested','ready_for_ios_boot')),
            'Full concrete display kernel link evidence is stale or overstates runtime execution')
    for name,digest in display_kernel['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'Full display dependency changed: '+name)
    for field in ('partial_object','isolated_kernel','input_manifest','command_manifest'):
        require(sha(ROOT/display_kernel[field])==display_kernel[field+'_sha256'],'Full display artifact changed: '+field)
        identities[display_kernel[field]]=display_kernel[field+'_sha256']
    for path,digest in json.loads((ROOT/display_kernel['input_manifest']).read_text()).items():require(sha(ROOT/path)==digest,'Full display link input changed: '+path)
    require(sha(ROOT/display_kernel['native_filelist'])==display_kernel['native_filelist_sha256'],'Isolated display native filelist changed')
    from build_display_kernel import iobsd_hook
    require(iobsd_hook(late_overlay,(ROOT/display_kernel['isolated_kernel']).read_bytes())==display_kernel['actual_iobsd_hook'],'Actual native IOBSD scheduling call changed')
    for path,digest in display_kernel['protected_default_artifact_sha256'].items():require(sha(ROOT/path)==digest,'Existing kernel/default changed: '+path)
    from build_display_kernel import concrete_table
    late=next(ROOT/o['path'] for o in service['objects'] if o['path'].endswith('DodgeIPhoneFramebuffer.late.o'))
    require(concrete_table(late,(ROOT/display_kernel['isolated_kernel']).read_bytes())==display_kernel['concrete_vtable'],'Actual full display vtable changed')
    display_prelink=reports['ios16-display-prelink']
    require(display_prelink['builder_sha256']==sha(ROOT/'scripts/build_display_prelink.py') and
            display_prelink['display_kernel_report_sha256']==sha(ROOT/'reports/ios16-display-kernel.json') and
            display_prelink['graphics_lifecycle_report_sha256']==sha(ROOT/'reports/ios16-graphics-lifecycle.json') and
            display_prelink['isolated_native_input_sha256']==display_kernel['isolated_kernel_sha256'] and
            display_prelink['original_kernelcache_sha256']==life['original_kernelcache_sha256'] and display_prelink['linked_source_objects']==64 and
            len(display_prelink['components'])==len(display_prelink['original_executable_segments'])==27 and len(display_prelink['kernel_interfaces'])==7 and
            display_prelink['pointer_sites_read_back']==sum(display_prelink['pointer_counts'].values())==58962 and
            display_prelink['original_binding_count']==len(display_prelink['original_display_aliases'])==196 and
            display_prelink['concrete_vtable_entries_read_back']==338 and display_prelink['original_legacy_vtable_words_read_back']==340 and
            display_prelink['module_constructor_entries_read_back']==display_prelink['module_finalizer_entries_read_back']==53 and
            display_prelink['native_source_entries_preserved']==42 and display_prelink['early_security_entries_read_back']==2 and
            display_prelink['actual_iobsd_hook']==display_kernel['actual_iobsd_hook'] and
            display_prelink['original_gop_provider_vtable_entries_read_back']==178 and display_prelink['original_gop_metadata_vtable_entries_read_back']==14 and
            display_prelink['gop_provider_contract_sha256']==gop['contract_sha256'] and
            all(display_prelink[k] for k in ('strict_emission','concrete_class_and_module_entry_linked','default_artifacts_unchanged',
                'original_executable_bytes_unchanged','native_executable_bytes_unchanged','source_crypto_post_field_verified')) and
            display_prelink['darwinboot_production_parser']=='PASS' and
            not any(display_prelink[k] for k in ('allow_missing','substitute_addresses','runtime_entry_invoked','runtime_provider_registered',
                'initializer_lifecycle_qualified','abi_qualified','loadable','runtime_qualified','default_kernel_selected','boot_payload_packaged',
                'hardware_tested','ready_for_ios_boot')),
            'Full display/original graphics prelink is stale or overstates initialization/runtime qualification')
    require([c['case'] for c in display_prelink['negative_readback_controls']]==['pointer','original-code','post-field','native-code','absolute-alias',
                'concrete-vtable','display-original-alias','graphics-metadata-alias','gop-provider-vtable','gop-provider-metadata-alias'] and all(c['result']=='REJECTED' for c in display_prelink['negative_readback_controls']),
            'Full display prelink corruption controls are incomplete')
    for path,digest in display_prelink['source_sha256'].items():require(sha(ROOT/path)==digest,'Full display prelink source changed: '+path)
    for field in ('candidate','sealed_native','emission_record','post_record','sealed_post_record'):
        require(sha(ROOT/display_prelink[field])==display_prelink[field+'_sha256'],'Full display prelink artifact changed: '+field)
        identities[display_prelink[field]]=display_prelink[field+'_sha256']
    for path,digest in display_prelink['protected_default_artifact_sha256'].items():require(sha(ROOT/path)==digest,'Existing default/GPU artifact changed: '+path)
    full_lifecycle=reports['ios16-display-kernel-lifecycle']
    require(full_lifecycle['builder_sha256']==sha(ROOT/'scripts/check_display_kernel_lifecycle.py') and
            full_lifecycle['native_kernel_sha256']==sha(NATIVE) and
            full_lifecycle['original_kernelcache_sha256']==display_prelink['original_kernelcache_sha256'] and
            full_lifecycle['candidate_sha256']==display_prelink['candidate_sha256'] and
            full_lifecycle['unicorn_version']=='2.1.4' and full_lifecycle['concrete_instance_bytes']==service['concrete_instance_bytes']==5768 and
            full_lifecycle['case_count']==len(full_lifecycle['cases'])==32 and all(c['result']=='PASS' for c in full_lifecycle['cases']) and
            full_lifecycle['original_thread_dispatcher_cases']==3 and full_lifecycle['provider_after_detach_and_external_release_cases']==2 and
            full_lifecycle['original_new_user_client_method_body_cases']==5 and full_lifecycle['source_client_admission_refusal_cases']==3 and
            full_lifecycle['client_allocator_metadata_init_attach_start_close_are_peers'] and not full_lifecycle['original_client_implementation_lifecycle_qualified'] and
            set(full_lifecycle['original_functions'])=={'init','start','stop','free','thread-start-helper','thread-dispatcher',
                'thread-body','post-hardware-285','default-attributes','get-work-loop','cleanup-275','new-user-client'} and
            all(full_lifecycle[k] for k in ('original_full_init_start_stop_free_instructions_executed','actual_concrete_class_instructions_executed',
                'actual_native_ioservice_start_leaf_executed','provider_lifetime_pin_until_source_free',
                'iokit_core_platform_function_matching_and_scheduler_are_peers','unknown_native_implementation_call_rejected',
                'original_instruction_bytes_unchanged','native_instruction_bytes_unchanged','default_artifacts_unchanged')) and
            not any(full_lifecycle[k] for k in ('original_surface_5056_path_executed','real_iokit_instance_constructed',
                'original_loader_executed','real_kernel_scheduler_executed','runtime_qualified','default_kernel_selected','hardware_tested','ready_for_ios_boot')),
            'Full linked display lifecycle CPU evidence is stale, incomplete or overstates runtime scope')
    require([c['case'] for c in full_lifecycle['negative_controls']]==['lost-provider-lifetime-pin','unreviewed-native-allocator'] and
            all(c['result']=='REJECTED' for c in full_lifecycle['negative_controls']),
            'Full linked lifecycle lacks its late-provider and unknown-native controls')
    for name,digest in full_lifecycle['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'Full lifecycle dependency changed: '+name)
    for path,digest in full_lifecycle['source_sha256'].items():require(sha(ROOT/path)==digest,'Full lifecycle source changed: '+path)
    for field in ('candidate','cpu_cases'):
        require(sha(ROOT/full_lifecycle[field])==full_lifecycle[field+'_sha256'],'Full lifecycle artifact changed: '+field)
        identities[full_lifecycle[field]]=full_lifecycle[field+'_sha256']
    cpu_cases=json.loads((ROOT/full_lifecycle['cpu_cases']).read_text())
    require(cpu_cases['cases']==full_lifecycle['cases'] and cpu_cases['negative_controls']==full_lifecycle['negative_controls'],
            'Full lifecycle CPU case record differs from its report')
    for path,digest in full_lifecycle['protected_default_artifact_sha256'].items():require(sha(ROOT/path)==digest,'Existing default/GPU artifact changed during lifecycle CPU check: '+path)
    gop_cpu=reports['ios16-gop-provider-kernel']
    require(gop_cpu['builder_sha256']==sha(ROOT/'scripts/check_gop_provider_kernel.py') and gop_cpu['native_kernel_sha256']==sha(NATIVE) and
            gop_cpu['candidate_sha256']==display_prelink['candidate_sha256'] and gop_cpu['original_kernelcache_sha256']==gop['original_kernelcache_sha256'] and
            gop_cpu['unicorn_version']=='2.1.4' and gop_cpu['original_instance_bytes']==216 and
            gop_cpu['case_count']==len(gop_cpu['cases'])==18 and all(c['result']=='PASS' for c in gop_cpu['cases']) and
            gop_cpu['actual_iobsd_hook_and_opt_in_schedule_cpu_cases']==4 and not gop_cpu['worker_executed_by_iobsd_caller'] and
            all(gop_cpu[k] for k in ('actual_original_allocator_and_native_parent_constructors_executed',
                'actual_source_factory_early_guards_and_unwind_executed','actual_original_get_resources_fast_path_executed',
                'original_get_meta_class_identity_executed','allocation_metadata_reference_public_init_and_registry_are_peers',
                'original_instruction_bytes_unchanged','default_artifacts_unchanged')) and
            not any(gop_cpu[k] for k in ('actual_service_publication_executed','original_loader_executed','real_iokit_instance_constructed',
                'runtime_qualified','default_kernel_selected','hardware_tested','ready_for_ios_boot')) and
            [c['case'] for c in gop_cpu['negative_controls']]==['unknown-native-allocator','nonzero-typed-allocation'] and
            all(c['result']=='REJECTED' for c in gop_cpu['negative_controls']),
            'Linked GOP factory and original allocation CPU evidence is stale or overstates runtime scope')
    for name,digest in gop_cpu['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'GOP CPU dependency changed: '+name)
    for path,digest in gop_cpu['source_sha256'].items():require(sha(ROOT/path)==digest,'GOP CPU source changed: '+path)
    for field in ('candidate','cpu_cases'):
        require(sha(ROOT/gop_cpu[field])==gop_cpu[field+'_sha256'],'GOP CPU artifact changed: '+field);identities[gop_cpu[field]]=gop_cpu[field+'_sha256']
    gop_cases=json.loads((ROOT/gop_cpu['cpu_cases']).read_text())
    require(gop_cases['cases']==gop_cpu['cases'] and gop_cases['negative_controls']==gop_cpu['negative_controls'],'GOP CPU record differs from report')
    payload=reports['ios16-display-payload']
    require(payload['builder_sha256']==sha(ROOT/'scripts/build_display_payload.py') and
            payload['candidate_sha256']==display_prelink['candidate_sha256'] and payload['linked_source_objects']==64 and
            payload['native_source_entries']==42 and payload['original_graphics_components']==27 and payload['original_interfaces']==7 and
            payload['boot_header_version']==4 and payload['boot_payload_packaged'] and payload['default_artifacts_unchanged'] and
            payload['unified_graphics_boot_entry_linked'] and payload['original_graphics_embedded'] and payload['phone_operations']=='none' and
            payload['real_class_gop_provider_factory_and_late_entry_linked'] and not payload['gop_provider_automatically_published'] and
            payload['opt_in_iobsd_graphics_hook_linked'] and payload['late_graphics_boot_requires_explicit_argument'] and
            not any(payload[k] for k in ('unified_graphics_boot_entry_automatically_invoked','original_userspace_included',
                'private_seed_disclosed','default_kernel_selected','runtime_qualified','hardware_tested','ready_for_ios_boot')),
            'Isolated display container is stale or overstates iOS runtime/boot qualification')
    for name,digest in payload['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'Display payload dependency changed: '+name)
    for path,digest in payload['source_sha256'].items():require(sha(ROOT/path)==digest,'Display payload source changed: '+path)
    for path,digest in payload['host_tools_sha256'].items():require(sha(ROOT/path)==digest,'Display payload host tool changed: '+path)
    for path,digest in payload['artifacts'].items():
        require(sha(ROOT/path)==digest,'Display payload artifact changed: '+path);identities[path]=digest
    for path,digest in payload['protected_default_artifact_sha256'].items():require(sha(ROOT/path)==digest,'Existing default/input changed during packaging: '+path)
    for binary in reports['gpu-userspace']['binaries']:
        require(sha(ROOT / binary['path']) == binary['sha256'], 'Userspace binary changed after page-integrity validation')
        identities[binary['path']] = binary['sha256']
    report = {'result': 'CPH2653_IOS16_GPU_OFFLINE_SOURCE_CANDIDATE_PASS', 'target': 'OnePlus 13 CPH2653 / iPhone iOS 16.7.16 / 20H392',
              'native_kernel_sha256': sha(NATIVE), 'kernel_candidate_objects': candidate['object_count'],
              'stages': {name: {'report': 'reports/' + name + '.json', 'result': value['result'],
                               'report_sha256': sha(ROOT / 'reports' / (name + '.json'))} for name, value in reports.items()},
              'artifacts': identities, 'required_display_provider_imports': candidate['imports']['required_board_or_original_imports'],
              'native_static_link_only_imports': candidate['imports']['native_static_link_only_imports'],
              'original_accelerator_base_static_audited': True, 'full_original_graphics_abi_qualified': False,
              'framebuffer_legacy_iphone_size': 5728, 'framebuffer_legacy_iphone_vtable_entries': 338,
              'offline_metal_pipelines': translation['pipelines'], 'validated_spirv_modules': len(translation['spirv_modules']),
              'offline_a830_machine_programs': len(ir3['cases']) + len(ir3['translated_spirv_cases']),
              'software_refresh_candidate_rate_hz': 60, 'real_panel_vblank_qualified': False,
              'isolated_native_link_probe_passed': True,
              'coherent_adreno_display_snapshot_compiled_and_cpu_checked': True,
              'isolated_original_graphics_strict_prelink_passed': True,
              'isolated_original_graphics_components': 27, 'isolated_graphics_pointer_readbacks': 58962,
              'unselected_optional_diagnostics': sorted(link['optional_weak_absence']),
              'kernel_integration_complete': False, 'default_kernel_selected': False, 'owner_trust_installed': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'bounded_packet_queue_frontend_compiled': True, 'concrete_legacy_display_provider_installed': False,
              'concrete_legacy_source_class_compiled':True,'concrete_source_service_lifecycle_host_cases':60,
              'concrete_source_service_arm64_cases':69,'concrete_source_service_integration_host_cases':10,
              'original_graphics_prepare_and_attach_source_compiled':True,'graphics_module_orchestration_host_cases':33,
              'unified_graphics_boot_source_compiled':True,'graphics_boot_ordering_host_cases':24,
              'concrete_display_full_kernel_source_objects':64,'concrete_display_original_aliases':196,
              'real_class_gop_provider_source_compiled':True,'gop_provider_ownership_host_cases':60,'linked_gop_provider_cpu_cases':18,
              'real_class_gop_provider_runtime_published':False,
              'opt_in_iobsd_graphics_hook_compiled':True,'late_graphics_scheduling_host_cases':24,'native_iobsd_hook_cpu_cases':4,
              'late_graphics_boot_argument_enabled_by_default':False,
              'concrete_display_full_kernel_and_original_graphics_prelink_passed':True,
              'linked_original_display_lifecycle_cpu_cases':32,'concrete_display_instance_bytes':5768,
              'original_new_user_client_method_body_cpu_cases':5,
              'provider_lifetime_preserved_for_late_original_thread':True,'full_original_display_lifecycle_runtime_qualified':False,
              'board_metal_registration_cleanup_host_cases':15,
              'board_atomic_startup_entry_host_cases':6,
              'isolated_display_development_container_packaged':True,'isolated_display_boot_image':payload['boot_image'],
              'remaining': ['Qualify the full original loader and parent start/stop on actual objects, including original user-client creation and power lifecycle.',
                            'Qualify original request retirement, actual IOSurface producer fences/cache visibility and GPU failure quiescence.',
                            'Invoke the real post-VM console attachment only after display mapping/ownership is qualified.',
                            'Qualify runtime original-object lifetime and mutation serialization for the compiled frontend/backing connection.',
                            'Complete original IOGPU/IOSurface/IOMobileGraphicsFamily ABI and initialization lifecycle audit.',
                            'Qualify actual command-db/fused SKU, shared rail ownership, SMMU/cache ownership and reset recovery.',
                            'Qualify late invocation of the compiled real-class GOP publisher and unified module/preflight/A830/display entry after IOBSD and original-service matching.',
                            'Verify real queue/fence/shader pixels and scanout on hardware when separately authorized.'],
              'scope': 'Current real kernel-side candidate, stock inputs, Rust bridge, Turnip and Metal binary builds with offline checks. No phone operations.'}
    (ROOT / 'reports/gpu-stack.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(reports)} current GPU source/build/test stages; source display imports resolved; frontend/kernel integration remains incomplete')


if __name__ == '__main__':
    main()
