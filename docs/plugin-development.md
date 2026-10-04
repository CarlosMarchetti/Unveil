# Extensão de componentes

O SDK inicial é uma API Python interna, ainda sem carregamento de manifests de terceiros.

Um analisador define `id`, `artifact_types` e `analyze(context)`. Ele adiciona findings e diagnósticos ao contexto e retorna `context.report(metadata)`. Registre-o explicitamente em `unveil.core.engine.analyzers()`:

```python
class ExampleAnalyzer:
    id = 'example.audit'
    artifact_types = ('CLASS',)

    def analyze(self, context):
        context.finding('example.observation', ['evidence'], [], confidence=50)
        return context.report({'example': True})

registry.register(ExampleAnalyzer(), api_version='1')
```

O dispatcher seleciona um analisador compatível. Para compor múltiplas análises do mesmo formato, faça a composição dentro desse analisador; o registro não agrega automaticamente todos os analisadores compatíveis.

Transformadores declaram `requires`, `runs_after`, `runs_before` e expõem `plan(model)`. Veja `unveil.jvm.transforms` para os três adaptadores existentes. O pipeline de aplicação JVM ainda conhece seus três passes e a etapa de metadata cleanup; um quarto transform exige integrar também sua aplicação e seu relatório. O registro sozinho não oferece plugins de transformação de ponta a ponta.

Versão diferente de `1`, IDs repetidos, dependências ausentes e ciclos são rejeitados. Registrar código é executá-lo com as permissões do processo. A lista de capacidades não é uma sandbox; plugins externos e manifests declarativos serão tratados em uma etapa posterior.
