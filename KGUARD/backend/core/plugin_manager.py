import importlib
import pkgutil
import os
from pathlib import Path

class PluginManager:
    def __init__(self):
        self.plugins = {}
        self.load_plugins()
    
    def load_plugins(self):
        plugins_dir = Path(__file__).parent.parent / 'modules'
        
        for file in plugins_dir.glob('*.py'):
            if file.name.startswith('__'):
                continue
            
            module_name = file.stem
            try:
                module = importlib.import_module(f'modules.{module_name}')
                if hasattr(module, 'scan'):
                    self.plugins[module_name] = {
                        'name': getattr(module, 'NAME', module_name),
                        'description': getattr(module, 'DESCRIPTION', ''),
                        'module': module
                    }
            except Exception as e:
                print(f"Error loading plugin {module_name}: {e}")
    
    def get_available_plugins(self):
        return [
            {'id': k, 'name': v['name'], 'description': v['description']}
            for k, v in self.plugins.items()
        ]
    
    def run_plugin(self, plugin_id, target):
        if plugin_id in self.plugins:
            return self.plugins[plugin_id]['module'].scan(target)
        return []
