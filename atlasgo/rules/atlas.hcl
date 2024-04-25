# Arquivo: database_validation.hcl

# Defina as regras para validação
rule "Deny GRANT, DROP DATABASE, and ALTER DATABASE"
{
  condition = contains("GRANT", input.script) || contains("DROP DATABASE", input.script) || contains("ALTER DATABASE", input.script)
  deny = true
  message = "Scripts com comandos GRANT, DROP DATABASE ou ALTER DATABASE não são permitidos."
}

# Exemplo de uso:
# input.script contém o conteúdo do script SQL a ser validado
