# DeltaSkin — skin mod menu cho Delta Force iOS

Dylib độc lập (arm64, iOS 14.0+). Chỉ có một chức năng: menu đổi skin súng. Không ESP, không aimbot,
không hook vào anti-cheat.

> Đọc `REPORT.md` để biết nó được dịch ngược từ đâu và cái gì **chưa** được kiểm chứng trên máy thật.

---

## 1. Build

**Cách A — tải bản build sẵn (không cần Mac):**
Repo: https://github.com/LuongLeTanTuan/DeltaSkin → tab **Actions** → run `build` mới nhất → tải artifact
`DeltaSkin-dylib` (giải nén ra `DeltaSkin.dylib`).

1. Push repo lên GitHub (workflow đã có sẵn trong `.github/workflows/build.yml`).
2. Tab **Actions** → workflow `build` → tải artifact `DeltaSkin-dylib`.
   Hoặc tạo tag `v1.0` để nó tự đính file vào Release: `git tag v1.0 && git push --tags`.

**Cách B — máy Mac có Xcode CLT:**
```bash
make            # -> build/DeltaSkin.dylib
```

Kết quả: `DeltaSkin.dylib` (~1 file, arm64).

---

## 2. Chèn vào IPA và cài

### iOS 18 — máy KHÔNG jailbreak
Đường duy nhất: IPA đã sideload + chèn dylib + ký lại (giống cách bản DeltaForceClient.app hiện tại đang
được ký bằng eSign — trong bundle có file `SignedByEsign`).

1. Mở **eSign** trên máy → `App List` → dấu `+` → chọn file IPA gốc của game.
2. Chọn app vừa import → **Signature** → mục **Inject Library** → thêm `DeltaSkin.dylib`.
3. Bật **Inject** (và tắt "Remove injected"? cứ để mặc định), chọn certificate của bạn → **Sign**.
4. Cài bản đã ký. Nếu game đã có sẵn `PxMenu/PxExtFFi` trong Frameworks thì **xoá hai cái đó** trước khi ký
   (không cần thiết cho skin, và chúng đang là thứ bị quét).
5. Mở game → sau ~2 giây thấy nút tròn **DS** góc trái trên → bấm để mở panel.

### iOS 14.8.1 — máy CÓ jailbreak (unc0ver/checkra1n/Taurine)
Cách 1 (đơn giản nhất): làm y hệt mục iOS 18 (chèn IPA + ký). Dylib không cần substrate nên chạy được.

Cách 2 (cài như tweak thật):
```bash
scp build/DeltaSkin.dylib root@<ip>:/Library/MobileSubstrate/DynamicLibraries/
ssh root@<ip> 'chmod 755 /Library/MobileSubstrate/DynamicLibraries/DeltaSkin.dylib; killall -9 SpringBoard'
```
Không cần file plist filter vì dylib chỉ tự khởi động khi process chứa nó load; nếu dùng Cydia Substrate
thì tạo `DeltaSkin.plist`:
```xml
{ Filter = { Bundles = ( "com.tencent.deltaforce" ); }; }
```
(kiểm tra bundle id thật trong `Info.plist` của app trước khi dùng).

---

## 3. Dùng menu

| Nút | Việc |
|---|---|
| **DS** (nút tròn) | mở/đóng panel |
| ô nhập | skin id: nhập số thập phân (`12345`) hoặc hex (`0x3039`) |
| **APPLY SKIN** | gọi setter skin cho mọi object súng tìm thấy |
| **RESTORE** | áp skin id `0` (về mặc định) |
| dòng trạng thái | `ready · GNames … · GObjects …` = tìm thấy engine; `no target matched (code -4)` = tên setter không khớp bản build này |

Mã lỗi trong trạng thái:
- `-1/-2` object/class không hợp lệ
- `-4` không tìm thấy UFunction setter nào (game đổi tên hoặc đổi lớp)
- `GNames not found` / `GObjects not found` = layout engine đổi → cần cập nhật magic/scan trong `DeltaSkin.mm`

Log chi tiết: Console.app hoặc `idevicesyslog | grep DeltaSkin`.

---

## 4. An toàn / rủi ro

- Chỉ đổi skin **phía client** (người khác không thấy, server không nhận). Đây là mức can thiệp thấp nhất.
- Dylib tự ngủ nếu phát hiện Frida hoặc debugger đang bám.
- Không sửa file game, không hook `anogs` (ACE), không tạo file lạ trên máy.
- **Không có bảo đảm miễn ban.** App bị ký lại + dylib lạ trong bundle vẫn là tín hiệu; dùng acc phụ để thử trước.

---

## 5. Gỡ

Xoá app đã cài (hoặc cài lại IPA gốc không chèn gì). Với máy jailbreak dùng cách 2: xoá file trong
`/Library/MobileSubstrate/DynamicLibraries/` rồi `killall -9 SpringBoard`.
