# DeltaSkin — skin mod menu cho Delta Force iOS

Dylib độc lập (arm64, iOS 14.0+). Chỉ có một chức năng: menu đổi skin súng. Không ESP, không aimbot,
không hook vào anti-cheat.

> Đọc `REPORT.md` để biết nó được dịch ngược từ đâu và cái gì **chưa** được kiểm chứng trên máy thật.

> **Có cách khác không chèn code:** [`dbpatch/`](dbpatch/) — sửa thẳng file dữ liệu SQLite mà
> game tự đọc (`DataTable.bytes`), không dylib, không hook, không đụng tiến trình game. Đang là
> hướng chính; phần dylib bên dưới giữ lại làm tham khảo.

**Tải về**

| File | Cho |
|---|---|
| [`DeltaSkin.tipa`](https://github.com/LuongLeTanTuan/DeltaSkin/releases/download/v1.0/DeltaSkin.tipa) | iOS 14 + TrollStore (mục 2A) |
| [`DeltaSkin.dylib`](https://github.com/LuongLeTanTuan/DeltaSkin/releases/download/v1.0/DeltaSkin.dylib) | chèn vào IPA bằng eSign (mục 2B) |

Chưa có Release thì lấy ở tab **Actions** → run `build` mới nhất → artifact (`DeltaSkin-tipa` /
`DeltaSkin-dylib`). Hai chỗ là cùng một file.

---

## 1. Build

**Cách A — tải bản build sẵn (không cần Mac):**
Repo: https://github.com/LuongLeTanTuan/DeltaSkin → tab **Actions** → run `build` mới nhất → tải artifact.
Có hai artifact trong cùng một run:

| Artifact | Nội dung | Dùng cho |
|---|---|---|
| `DeltaSkin-tipa` | `DeltaSkin.tipa` (~58 KB) = app `DeltaSkin.app` chứa sẵn `DeltaSkin.dylib` + nút **Patch** | **TrollStore / iOS 14** (mục 2A) |
| `DeltaSkin-dylib` | `DeltaSkin.dylib` (~137 KB, arm64) | chèn vào IPA bằng eSign/Sideloadly (mục 2B) |

1. Push repo lên GitHub (workflow đã có sẵn trong `.github/workflows/build.yml`).
2. Tab **Actions** → workflow `build` → tải artifact.
   Hoặc tạo tag `v1.0` để nó tự đính cả hai file vào Release: `git tag v1.0 && git push --tags`.

**Cách B — máy Mac có Xcode CLT:**
```bash
make            # -> build/DeltaSkin.dylib
```

Kết quả: `DeltaSkin.dylib` (~137 KB, arm64).

---

## 2. Cài

Có hai đường. Đường A dành cho máy đã cài **TrollStore** (iOS 14.0–14.8.1) và **không cần chèn IPA** —
cài một app nhỏ, bấm một nút. Đường B là cách cũ (chèn dylib vào IPA rồi ký lại), dùng khi không có
TrollStore.

### 2A. iOS 14 — TrollStore, cài `DeltaSkin.tipa` (khuyến nghị)

Đây là app **patcher độc lập**, không phải bản mod của game. Nó sửa đúng một lần vào file thực thi của
game rồi thôi.

1. Tải `DeltaSkin.tipa` (artifact `DeltaSkin-tipa`, hoặc file trong Release).
2. Mở TrollStore → dấu `+` → chọn `DeltaSkin.tipa` → **Install**.
3. Mở app **DeltaSkin** vừa cài. Dòng trạng thái phải hiện đường dẫn app game, ví dụ
   `/var/Containers/Bundle/Application/<UUID>/DeltaForceClient.app` và `state: untouched`.
   - App tìm game theo `CFBundleIdentifier = com.garena.game.df` trước, rồi mới tới tên file thực thi
     `DeltaForceClient`.
   - Nếu hiện `game not found`: game chưa cài, hoặc bản game nằm ở đường dẫn lạ.
4. Bấm **Patch**. Log sẽ chạy: `backup written` → `payload copied` → `done`.
5. Mở game. Sau ~2 giây thấy nút tròn **DS** ở **mép phải màn hình, khoảng 1/3 chiều cao** — kéo được.

App làm gì khi bấm **Patch** (đúng 4 việc, không hơn):

| Bước | Chi tiết |
|---|---|
| Sao lưu | chép `DeltaForceClient` (file thực thi) + `Info.plist` vào `Documents/backup/<bundle-id>/` của app DeltaSkin. Chỉ làm một lần; các lần Patch sau dùng lại bản gốc đó |
| Payload | chép `DeltaSkin.dylib` (nằm sẵn trong app) vào `DeltaForceClient.app/Frameworks/` |
| Chèn | thêm đúng **một** lệnh `LC_LOAD_DYLIB` = `@executable_path/Frameworks/DeltaSkin.dylib` vào header Mach-O. Không có chỗ trống trong header thì báo lỗi và **không ghi gì** |
| Ký lại | băm lại toàn bộ file (SHA-256 từng page 4 KiB) và gắn lại chữ ký vào cuối. Entitlements của game và khối CMS cũ được đọc từ chính file đang sửa rồi mang sang — không ký bằng thứ gì khác |

Bấm **Restore original** để trả file thực thi + `Info.plist` về bản sao lưu và xoá dylib khỏi `Frameworks/`.
Gỡ app DeltaSkin sau đó cũng được, game vẫn chạy bình thường.

> **Lưu ý thật:** khâu ký lại là chỗ **chưa được kiểm chứng trên máy thật**. Chi tiết, giới hạn và
> cách xử lý nếu game không mở được: `REPORT.md` mục 6.

### 2B. Chèn dylib vào IPA rồi ký lại

#### iOS 18 — máy KHÔNG jailbreak
Đường duy nhất: IPA đã sideload + chèn dylib + ký lại (giống cách bản DeltaForceClient.app hiện tại đang
được ký bằng eSign — trong bundle có file `SignedByEsign`).

1. Mở **eSign** trên máy → `App List` → dấu `+` → chọn file IPA gốc của game.
2. Chọn app vừa import → **Signature** → mục **Inject Library** → thêm `DeltaSkin.dylib`.
3. Bật **Inject** (và tắt "Remove injected"? cứ để mặc định), chọn certificate của bạn → **Sign**.
4. Cài bản đã ký. Nếu game đã có sẵn `PxMenu/PxExtFFi` trong Frameworks thì **xoá hai cái đó** trước khi ký
   (không cần thiết cho skin, và chúng đang là thứ bị quét).
5. Mở game → sau ~2 giây thấy nút tròn **DS** góc phải trên → bấm để mở panel.

#### iOS 14.8.1 — máy CÓ jailbreak (unc0ver/checkra1n/Taurine)
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

Panel là **hai cột cạnh nhau**: cột trái danh sách súng, cột phải là skin **của đúng khẩu đang chọn**.
Chọn súng bên trái → cột phải đổi ngay sang skin của khẩu đó. Không còn ô nhập ID tự do, nên không có
chuyện "chọn ô này ra id khác".

| Thành phần | Việc |
|---|---|
| **DS** (nút tròn) | mở/đóng panel. Kéo được bằng ngón tay, kéo xong không mở menu (phân biệt tap với pan) |
| cột **trái** | 78 khẩu súng. Bấm một khẩu = chọn khẩu đó, cột phải nhảy về skin đầu tiên của nó |
| cột **phải** | skin của khẩu đang chọn (tổng 705 skin). Bấm một dòng = chọn skin đó |
| dòng `0x…` cạnh nút Apply | ID của skin đang chọn — chỉ đọc, luôn khớp với dòng vừa bấm |
| **Apply Skin** | gọi setter skin cho mọi object súng tìm thấy |
| **Default** | áp skin id `0` (về mặc định) |
| **runtime** | hiện `ready · 64 weapons / 705 skins / ace N/7` = bảng skin đã nạp + số hàm gửi report của ACE đã bị vô hiệu |
| dòng trạng thái | dưới tiêu đề, cập nhật kết quả từng lần Apply (`Skin 0x… applied to N object(s)` / `Nothing applied (code -4)`) |

Chạm ra vùng tối bên ngoài panel hoặc nút **✕** để đóng. Đóng xong menu **huỷ luôn window của nó**
(`windowScene = nil`, `hidden = YES`) và trả key window về cho game — đây là lý do bản trước bị
"tắt menu xong bấm ra ngoài không ăn": panel cũ nằm trong một view phủ toàn màn hình, view đó vẫn
nhận chạm dù panel đã ẩn.

Panel được **dựng lại mỗi lần mở** và canh theo `window.bounds` đang sống (Auto Layout), không dùng
`UIScreen.mainScreen.bounds` đo một lần lúc khởi động — đó là lý do bản trước panel nằm lệch và ô bấm
không trúng khi game đang ở landscape.

Danh sách súng và skin **lấy từ `PxExtFFi`** (framework UI của chính menu bên bán): 705 dòng
`(weapon, skinId, tên hiển thị đầy đủ "Súng - Skin")` tại `0x1CF05A8` + `0x1CF46A0`. Vì mỗi dòng đã
mang sẵn id và tên đầy đủ, việc chia nhóm suy ra từ chính chuỗi của nhà bán chứ không đoán. Kiểm tra:
64 nhóm, 705 dòng, 705 id khác nhau, 0 nhóm rỗng, 0 id trùng.

Bảng sinh lại bằng script, không sửa tay:

```
python tools\build_table.py     # sinh lại src/SkinTable.h từ PxExtFFi
python tools\verify_table.py    # dựng lại ds_load_table() và đối chiếu từng id
```

> Bản trước lấy bảng từ `PxMenu.dylib` (705 dòng chia theo 85 "khẩu"). 22 trong 85 tên đó thật ra là
> **một skin** bị đẩy lên làm tên súng (`ASh-12 Battle Rifle-Goose Goose Duck`…), nên chọn súng xong
> danh sách skin bên phải lệch hẳn. Thêm vào đó cách quét 4 byte cũ nhặt được **3 bản ghi ma** có id
> không tồn tại trong catalog — chọn đúng 3 dòng đó thì ra skin của khẩu khác. Xem `REPORT.md` mục 3.9.

> Nhóm cuối **Cận chiến & Khác** là 18 id melee/cosmetic của nhà bán. Chúng là dữ liệu thật nhưng menu
> này chỉ gọi setter trên descriptor của súng, nên áp id melee vào súng sẽ không ra đúng skin.

Mã lỗi trong trạng thái:
- `-1/-2` object/class không hợp lệ
- `-4` không tìm thấy UFunction setter nào (game đổi tên hoặc đổi lớp)
- `pool not found` / `objects not found` = layout engine đổi → cần cập nhật magic/scan trong `DeltaSkin.mm`

Log chi tiết: Console.app hoặc `idevicesyslog | grep DeltaSkin`.

---

## 4. An toàn / rủi ro

- Chỉ đổi skin **phía client** (người khác không thấy, server không nhận). Đây là mức can thiệp thấp nhất.
- Dylib tự ngủ nếu phát hiện Frida hoặc debugger đang bám.
- **Đường 2B** (chèn IPA) không sửa gì trên máy: mọi thứ nằm trong IPA đã ký lại.
- **Đường 2A** (TIPA) *có* sửa file thực thi của game — đúng một lệnh `LC_LOAD_DYLIB`, và giữ bản sao
  lưu file gốc. Bấm **Restore original** là về nguyên trạng.
- Không tạo file lạ ngoài thư mục backup của app DeltaSkin. `anogs` (ACE) **chỉ bị vô hiệu hoá 7 hàm gửi
  report** (`AnoSDKGetReportData*` / `AnoSDKDelReportData*`) — chi tiết ở `REPORT.md` mục 4.
- **Không có bảo đảm miễn ban.** App bị ký lại + dylib lạ trong bundle vẫn là tín hiệu; dùng acc phụ để thử trước.

---

## 5. Gỡ

- **Đường 2A:** mở app DeltaSkin → **Restore original** → xong thì xoá app DeltaSkin.
- **Đường 2B:** xoá app đã cài rồi cài lại IPA gốc không chèn gì.
- Máy jailbreak cài bằng Substrate: xoá file trong `/Library/MobileSubstrate/DynamicLibraries/`
  rồi `killall -9 SpringBoard`.
