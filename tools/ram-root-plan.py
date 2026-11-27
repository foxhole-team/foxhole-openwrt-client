"""Validate the separately budgeted Cudy WR3000 v1 RAM package deployment."""
import json


def validate_inputs(root, platform, plan_name, plan, helpers):
    universe = json.loads((root / platform['packageUniverse']['file']).read_bytes())
    packages = {row['name']: row for row in universe['packages']}
    auth = {row['name']: row for row in universe['packageAuthentications']}
    indexes = {row['file']: row for row in universe['repositoryIndexes']}
    keys = {row['file']: row for row in universe['trustKeys']}
    engine = next(row['entry'] for row in platform['clients'] if row['id'] == 'hysteria2' and row['storage'] == 'ram')
    selected, pending = set(), [platform['basePackage']['name'], engine['packageName']]
    while pending:
        name = pending.pop()
        if name not in selected:
            selected.add(name)
            pending.extend(universe['requires'][name])
    index_files = {auth[name]['indexFile'] for name in selected}
    key_files = {key for filename in index_files for key in indexes[filename]['trustKeyFiles']}
    inputs = {packages[name]['file'] for name in selected} | index_files | key_files | set(helpers)
    inputs.update([plan_name, 'package-catalog.json', platform['packageUniverse']['file'],
                   platform['engineCatalog']['file'], platform['stockFactoryInventory']['file'],
                   f"engine-hysteria2-{platform['architecture']}-{engine['binarySha256']}.bin"])
    for row in platform['clients']:
        if row['id'] == 'hysteria2':
            inputs.update(row[k]['file'] for k in ('producer', 'capabilities', 'slotManifest'))
    sizes = plan['bytes']
    actual = dict(selectedFlatInputBytes=sum((root / name).stat().st_size for name in inputs),
                  packageArchiveBytes=sum(packages[name]['archiveBytes'] for name in selected),
                  installedPackageBytes=sum(packages[name]['installedBytes'] for name in selected),
                  largestArchiveBytes=max(packages[name]['archiveBytes'] for name in selected),
                  repositoryIndexBytes=sum(indexes[name]['bytes'] for name in index_files),
                  trustKeyBytes=sum(keys[name]['bytes'] for name in key_files),
                  baseRuntimeMemoryBytes=universe['baseRuntimeMemoryBytes'],
                  ramReserveBytes=universe['ramReserveBytes'])
    if any(sizes.get(name) != total for name, total in actual.items()):
        raise ValueError('RAM capacity differs from the complete signed package and input closure')
    if plan['client'].get('packageIdentity') != auth[engine['packageName']]['packageIdentity']:
        raise ValueError('RAM module package identity differs from its signed index binding')


def validate(plan, platform, catalog_sha):
    board = platform['freshInstallBoard']
    if (plan.get('schema') != 1 or plan.get('kind') != 'ram-root-install-plan-v1' or
            plan.get('boardName') != board['boardName'] or board != {'boardName': 'cudy,wr3000-v1', 'storageMode': 'ram'} or
            plan.get('firmware') != '25.12.5' or plan.get('target') != 'mediatek/filogic' or
            plan.get('architecture') != 'aarch64_cortex-a53' or plan.get('storageMode') != 'ram' or
            plan.get('deployment') != 'isolated-apk-root' or plan.get('protocols') != ['hysteria2'] or
            plan.get('packageCatalogSha256') != catalog_sha or
            plan.get('packageUniverseSha256') != platform['packageUniverse']['sha256'] or
            plan.get('basePackageSha256') != platform['basePackage']['sha256'] or
            plan.get('coldBootRecovery') is not False or plan.get('hostApkWorldMutation') is not False or
            type(plan.get('hostPackageFlashBytes')) is not int or plan['hostPackageFlashBytes'] != 0 or
            plan.get('activationQualified') is not False):
        raise ValueError('Incorrect RAM-root identity or lifecycle policy')
    selected = [value['entry'] for value in platform['clients'] if value['id'] == 'hysteria2' and value['storage'] == 'ram']
    if len(selected) != 1:
        raise ValueError('Expected one verified RAM Hysteria2 descriptor')
    engine = selected[0]
    for key in ('packageSha256', 'indexSha256', 'executableSha256', 'capabilitiesSha256'):
        if plan['client'].get(key) != engine[key]:
            raise ValueError('RAM client identity differs')
    if plan['client'].get('volatileElfSha256') != engine['binarySha256'] or plan['client'].get('slotManifestSha256') != engine['manifestSha256']:
        raise ValueError('RAM native executable or slot differs')
    sizes = plan['bytes']
    if (not sizes or any(type(x) is not int or not 0 < x <= 2147483648 for x in sizes.values()) or
            sizes['volatileExecutableBytes'] != engine['binaryBytes'] or sizes['moduleRuntimeMemoryBytes'] != engine['runtimeMemoryBytes'] or
            sizes['baseRuntimeMemoryBytes'] < 67108864 or sizes['ramReserveBytes'] < 33554432):
        raise ValueError('RAM-root capacity inputs are invalid')
    steady = sizes['installedPackageBytes'] + sizes['volatileExecutableBytes'] + sizes['metadataAllowanceBytes']
    intake = (sizes['selectedFlatInputBytes'] + sizes['packageArchiveBytes'] + sizes['repositoryIndexBytes'] +
              sizes['trustKeyBytes'] + steady)
    phases = plan['phaseBytes']
    minimums = dict(download=sizes['selectedFlatInputBytes'] + sizes['transportArchiveBytes'] +
                    sizes['transportDescriptorBytes'] + sizes['outerManifestBytes'],
                    prepare=intake + 2 * sizes['largestArchiveBytes'] + sizes['nativeApkOverheadBytes'],
                    activation=steady + sizes['baseRuntimeMemoryBytes'] + sizes['moduleRuntimeMemoryBytes'],
                    rollback=steady + sizes['metadataAllowanceBytes'])
    if (set(phases) != set(minimums) or any(type(phases[k]) is not int or not minimums[k] <= phases[k] <= 2147483648 for k in phases) or
            plan['requiredMemAvailableBytes'] != max(phases.values()) + sizes['ramReserveBytes'] or
            plan['requiredTmpfsAvailableBytes'] != max(intake, phases['download'], phases['rollback']) + sizes['ramReserveBytes']):
        raise ValueError('RAM-root totals do not cover the distinct installation phases and reserve')
