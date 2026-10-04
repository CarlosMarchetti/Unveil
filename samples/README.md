# Exemplos reproduzíveis

Os geradores em `tests/framework_fixtures.py` produzem uma classe `Example.answer()` com bytecode `ICONST_1; ICONST_2; IADD; IRETURN` e arquivos PE32/PE32+ com tabelas conhecidas. A classe resulta em `LDC 3; IRETURN` após o pass de constantes. Não são necessários binários de terceiros.

Execute as integrações descritas no README para gerar os arquivos em `test-output/`. O gerador JVM completo cria pools e seis casos de recuperação de strings. Os PEs são arquivos de teste estrutural e nunca devem ser executados.

`jvm-plan.json`, `pe-analysis.json` e `pe-analysis.html` são relatórios produzidos pelo código sobre essas fixtures. Seus caminhos de entrada foram normalizados para que não exponham diretórios locais. Os hashes correspondem aos bytes das fixtures.
