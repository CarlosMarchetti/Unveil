"""Explicit registrations only; no scanning/import of untrusted plugins."""


class Registry:
    def __init__(self):
        self.items = {}

    def register(self, item, api_version='1'):
        if api_version != '1':
            raise ValueError('Unsupported plugin API version: ' + api_version)
        if item.id in self.items:
            raise ValueError('Duplicate component ID: ' + item.id)
        self.items[item.id] = item

    def ordered(self, selected=None):
        selected = set(self.items if selected is None else selected)
        unknown = selected - self.items.keys()
        if unknown:
            raise ValueError('Unknown components: ' + ', '.join(sorted(unknown)))
        edges = {name: set() for name in selected}
        for name in selected:
            item = self.items[name]
            required = set(getattr(item, 'requires', ()))
            if required - selected:
                raise ValueError('Missing dependencies for ' + name)
            edges[name].update(required | (set(getattr(item, 'runs_after', ())) & selected))
            for target in set(getattr(item, 'runs_before', ())) & selected:
                edges[target].add(name)
        ordered = []
        while edges:
            ready = sorted(name for name, dependencies in edges.items() if not dependencies)
            if not ready:
                raise ValueError('Component ordering cycle')
            for name in ready:
                ordered.append(self.items[name])
                del edges[name]
            for dependencies in edges.values():
                dependencies.difference_update(ready)
        return ordered
