from dataclasses import dataclass
from deobf import passes
from unveil.core.registry import Registry


@dataclass
class Transform:
    id: str
    planner: object
    runs_after: tuple = ()
    requires: tuple = ()
    runs_before: tuple = ()

    def plan(self, model):
        return self.planner(model)


def registry():
    result = Registry()
    result.register(Transform('constant', lambda m: passes.constants(m['classes'])))
    result.register(Transform('string-pool', lambda m: passes.pool_uses(m['classes'], m['pools']), ('constant',)))
    result.register(Transform('string-decrypt', lambda m: passes.decrypt(m['classes'], m['decryptors'], m['pools'])[0], ('string-pool', 'constant')))
    return result
