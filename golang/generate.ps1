<#
.SYNOPSIS
    Compila um pacote Go para múltiplas plataformas e arquiteturas.

.DESCRIPTION
    Este script PowerShell compila um pacote Go para uma lista extensa de plataformas (Windows, macOS, Linux)
    e arquiteturas. Para cada compilação, ele cria uma estrutura de diretórios correspondente
    (ex: 'linux/amd64') e salva o executável resultante nessa pasta.

.PARAMETER Package
    O caminho do pacote Go a ser compilado. Por exemplo: 'github.com/seu-usuario/seu-repo'.
    Este parâmetro é obrigatório.

.EXAMPLE
    .\seu_script.ps1 -Package "github.com/meu-usuario/meu-projeto"

    Este comando irá compilar o pacote 'meu-projeto' para todas as plataformas listadas
    e organizar os binários em pastas como 'windows/amd64', 'linux/arm64', etc.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "O pacote Go a ser compilado")]
    [string]$Package
)

# A linha a seguir substitui: package_split=(${package//\// }) e package_name=${package_split[-1]}
# Usamos o método .Split() para dividir a string e selecionamos o último elemento com '[-1]'.
$packageName = $Package.Split('/')[-1]

# Lista de plataformas de destino expandida.
$platforms = @(
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm64",
    "linux/arm",
    "linux/386",
    "windows/386",
    "windows/amd64",
    "windows/arm64"
)

# O loop 'foreach' do PowerShell itera sobre cada plataforma.
foreach ($platform in $platforms) {
    
    # Divide a string da plataforma para obter o SO e a Arquitetura.
    $platformSplit = $platform.Split('/')
    $GOOS = $platformSplit[0]
    $GOARCH = $platformSplit[1]

    # Define o nome do diretório de saída com base na plataforma.
    $outputDir = $platform

    # Verifica se o diretório de saída não existe e, em caso afirmativo, cria-o.
    # O comando 'New-Item' com '-ItemType Directory' cria uma nova pasta.
    if (-not (Test-Path -Path $outputDir -PathType Container)) {
        Write-Host "Criando diretório: $outputDir"
        New-Item -Path $outputDir -ItemType Directory | Out-Null
    }

    # Monta o nome do arquivo de saída.
    $outputFileName = "$($packageName)-$($GOOS)-$($GOARCH)"

    # Adiciona a extensão .exe para builds do Windows.
    if ($GOOS -eq "windows") {
        $outputFileName += ".exe"
    }

    # Usa Join-Path para construir de forma segura o caminho completo do arquivo de saída.
    $fullOutputPath = Join-Path -Path $outputDir -ChildPath $outputFileName

    Write-Host "Compilando para $($GOOS)/$($GOARCH)..."

    # Define as variáveis de ambiente para o processo de compilação do Go.
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH

    # Executa o comando de build do Go, especificando o caminho de saída completo.
    go build -o $fullOutputPath $Package

    # Verifica o código de saída do último comando executado.
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Ocorreu um erro durante a compilação para $($platform)! Abortando a execução do script..."
        exit 1
    }
}

Write-Host "Builds concluídos com sucesso! Os arquivos estão organizados nas respectivas pastas."
