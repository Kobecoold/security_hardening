# Hướng dẫn Cấu hình WinRM trên Windows 10/11/Server

## Vấn đề
Khi audit Windows server, bạn có thể gặp lỗi:
```
Connection refused on port 5985 (HTTP) or 5986 (HTTPS)
```

Điều này có nghĩa là **WinRM chưa được enable hoặc cấu hình** trên Windows.

---

## Giải pháp: Cấu hình WinRM trên Windows

**Lưu ý:** Chỉ cần cấu hình **MỘT LẦN** trên Windows endpoint, sau đó có thể audit/remediate từ xa mãi mãi.

### Bước 1: Mở PowerShell as Administrator

Trên Windows server, click chuột phải vào PowerShell và chọn **"Run as Administrator"**

### Bước 2: Enable WinRM Service

```powershell
# Kiểm tra WinRM service status
Get-Service WinRM

# Enable WinRM service
Enable-PSRemoting -Force
```

### Bước 3: Cấu hình WinRM

```powershell
# Quick config WinRM (sẽ tự động cấu hình listener và firewall)
winrm quickconfig
```

Khi được hỏi, chọn **Y** (Yes) cho tất cả các câu hỏi.

### Bước 4: Cho phép WinRM qua Firewall

```powershell
# Enable firewall rules cho WinRM
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
```

### Bước 5: Kiểm tra WinRM Listeners

```powershell
# Kiểm tra listeners đã được tạo
winrm enumerate winrm/config/Listener
```

Bạn sẽ thấy output như:
```
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Hostname
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint
    ListeningOn = ...

Listener
    Address = *
    Transport = HTTPS
    Port = 5986
    ...
```

### Bước 6: Cấu hình Authentication (nếu cần)

```powershell
# Cho phép Basic authentication (nếu cần)
winrm set winrm/config/service/auth '@{Basic="true"}'

# Cho phép unencrypted traffic (chỉ dùng trong môi trường nội bộ)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

⚠️ **Lưu ý**: Cho phép unencrypted chỉ nên dùng trong môi trường nội bộ an toàn.

---

## Kiểm tra từ Linux Server

Sau khi cấu hình trên Windows, test từ Linux server:

```bash
# Test WinRM connection (nếu có winrm-cli)
winrm-cli -hostname <windows-ip> -username <username> -password <password> -transport http "echo test"

# Hoặc test bằng telnet
telnet <windows-ip> 5985
telnet <windows-ip> 5986
```

---

## Troubleshooting

### Lỗi: "Access Denied"
- Đảm bảo user có quyền Administrator hoặc được thêm vào Remote Management Users group
- Kiểm tra UAC settings

### Lỗi: "Connection Refused"
- Kiểm tra WinRM service: `Get-Service WinRM`
- Kiểm tra firewall: `Get-NetFirewallRule -DisplayGroup "Windows Remote Management"`
- Kiểm tra network connectivity: `Test-NetConnection -ComputerName <server> -Port 5985`

### Lỗi: "Authentication Failed"
- Kiểm tra username/password
- Thử với domain account nếu là domain environment
- Kiểm tra LocalAccountTokenFilterPolicy:
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1
  ```

### Kiểm tra WinRM Configuration

```powershell
# Xem cấu hình WinRM hiện tại
winrm get winrm/config
winrm get winrm/config/service
winrm get winrm/config/client
```

---

## Security Best Practices

1. **Sử dụng HTTPS (port 5986)** thay vì HTTP khi có thể
2. **Không enable unencrypted traffic** trong production
3. **Giới hạn IP addresses** có thể kết nối WinRM
4. **Sử dụng certificates** cho authentication
5. **Audit WinRM access** logs

---

## Tham khảo

- [Microsoft WinRM Documentation](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)
- [Enable-PSRemoting](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting)

