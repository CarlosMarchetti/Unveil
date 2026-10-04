# Contribuição

Use Python 3.10+ e JDK 8+. Instale `requirements.txt`; o primeiro build do helper baixa ASM. Não publique JARs ou executáveis de terceiros. Fixtures devem ser geradas pelo projeto e possuir origem clara.

```powershell
python -m pip install -r requirements-dev.txt
python -c "from deobf.writer import build; build()"
python -m unittest discover -s tests -v
python tests/integration.py
python tests/names_integration.py
python tests/framework_integration.py
```

A integração do framework depende das fixtures geradas pela primeira integração. Somente as fixtures Java de autoria do projeto são executadas. Os PEs sintéticos são exclusivamente dados de teste.

Mudanças em transforms devem demonstrar preservação de semântica e verificação da saída. Mudanças nos parsers devem incluir entradas truncadas ou inválidas. Descreva limitações e atualize a documentação e o schema quando alterar contratos públicos.

A licença do projeto ainda depende de decisão do titular. Essa decisão deve anteceder contribuições externas relevantes, conforme a proposta.
