# Báo cáo dịch ngược menu hack Delta Force (PxExtFFi / PxMenu) + bản clone DeltaSkin

Ngày: 01/11/2026. Mục tiêu: tách riêng chức năng **mod skin**, bỏ toàn bộ phần còn lại của menu bán sẵn, dựng lại thành project tự build cho iOS 18 (không jailbreak) và iOS 14.8.1 (có jailbreak).

---

## 1. Hiện trạng thư mục (đã kiểm tra trực tiếp)

```
D:\dfgpt\DeltaForceClient.app\
  DeltaForceClient            416 MB   binary chính (UE5, Tencent INTLSDK/GCloud/CrashSight)
  Frameworks\
    PxExtFFi.framework\PxExtFFi   31.5 MB  framework "giả dạng" — dylib nền tảng của menu
    PxMenu.dylib                 177 KB   <-- UI menu + logic mod skin (self-contained)
    AnoMute.dylib                69 KB    (không liên quan skin)
    anogs.framework                       Tencent ACE (Anti-Cheat Expert)
    CrashSight*, DataDomeSDK, TDMASA ...  analytics/anti-fraud của game
  PxExtFFi.framework\PxExtFFi.id0/.id1/.nam/.til   database IDA sót lại của lần phân tích trước
```

Điểm quan trọng số 1: **PxExtFFi không phải nơi chứa logic skin**. Toàn bộ phần skin nằm trong `PxMenu.dylib`
dưới lớp Objective-C `PxUE4`. Vì vậy bản clone **không cần** framework 31 MB kia, không cần bất cứ thứ gì
đã bị làm rối trong đó.

Bằng chứng:
- `install_name` của `PxExtFFi` = `/Library/MobileSubstrate/DynamicLibraries/NativeMenuObjC.dylib`
  → là tweak dylib đổi tên thành framework để núp trong bundle.
- Cả hai dylib chỉ link framework hệ thống (Foundation, UIKit, Metal, Security, libz…), **không link**
  substrate/fishhook/ShadowHook → chúng tự cài inline hook bằng `mprotect`/`mach_vm_protect` nếu cần.
- Danh sách lớp ObjC trong `PxMenu.dylib`: `PxControl, PxSection, PxStore, PxTab, PxMenuView, PxOverlay,
  PxUE4, PxFloatingButton` — tức là toàn bộ menu (UI + engine access) nằm gọn trong 177 KB này.

---

## 2. Chuỗi skin lấy được từ `PxMenu.dylib`

Địa chỉ là offset file, trích từ `strings` + IDA Hex-Rays 9.1 (chạy headless, log `D:\dfgpt\work\pxmenu.log`).

```
0x18d26  SetSkin
0x18d2e  SetSkin_BS
0x18d39  SetSkin_ES
0x18d44  SetSkinInfo
0x18d50  SetSkinApperanceId
0x18d63  ApplySkin
0x18d6d  SetSkinId
0x16cc8  Apply Skin
0x16cfc  "Skin 0x%X applied via descriptor."
0x16d1e  "Skin 0x%X applied via Appearance Data Component."
0x16d4f  "Skin 0x%X applied via descriptor + Data Component."
0x16d82  "Skin 0x%X applied via Appearance Func Component."
0x16db3  "Skin 0x%X applied via all components (hops 0x%lX)."
0x16e66  "SetSkin setter functions not found."
0x16c2c  skin_weapon_idx / 0x16c66 skin_select_idx / 0x16c7d skin_gun_id
0x16e... "com.chunmodvn.deltasdk.modskin.v1"   (suite NSUserDefaults của menu gốc)
0x1cc708e (trong PxExtFFi) "Applying gun skin via SDK..."
```

Tên lớp engine cần thiết (hằng chuỗi trong `PxMenu`):

```
ModularWeaponDesc            (fallback: GPModularWeaponDesc)
ModularWeaponDataComponentAppearance
ModularWeaponFuncComponentAppearance
```

---

## 3. Thuật toán thật của menu gốc (đã đọc pseudocode, không phải phỏng đoán)

### 3.1 Tìm vùng nhớ (sub_ED64)
Duyệt `mach_vm_region_recurse`, lưu tối đa 0x2000 cặp `[start,end)` vào `qword_266A8[] / qword_366A8[]`.
Mọi lần deref pointer thô sau đó đều đi qua tìm kiếm nhị phân trong bảng này trước (fail-closed → trả 0).
Đây là lý do menu gốc không crash khi offset sai.

### 3.2 Tìm host image `-[PxUE4 scanIfNeeded]`
```
_dyld_image_count / _dyld_get_image_name  -> basename == "DeltaForceClient"
_dyld_get_image_header  (kiểm tra MH_MAGIC_64)
_dyld_get_image_vmaddr_slide
duyệt load_command: LC_SEGMENT_64, segname bắt đầu bằng "__DATA" -> lưu tối đa 8 vùng
                     segname bắt đầu bằng "__TEXT" -> lưu tối đa 4 vùng (để validate con trỏ hàm)
```

### 3.3 Tìm GNames
Quét từng 8 byte trong các vùng `__DATA`, tìm con trỏ `p` sao cho:

```
*(uint32*)p == 0x6F4E0008      // header FNameEntry: Len = 8>>1 = 4, ANSI  + "No"
*(uint16*)(p+4) == 0x656E      // "ne"   -> tên "None"
```

rồi kiểm tra `p[1..4]` là con trỏ entry hợp lệ (hoặc NULL). Kết quả `qword_263B8 = p` chính là
`FNameEntryAllocator::Blocks[]` (pool). Xác thực thêm bằng cách đọc tên index 0 và so với "None".

→ Vậy format tên trong bản dựng này là **UE5**: `uint16 header; bit0 = wide; len = header >> 1;`
không phải layout UE4 cũ (int16 header).

### 3.4 Tìm GObjects
Quét tiếp `__DATA` tìm con trỏ tới **mảng con trỏ chunk**:
- `chunk_i = arr[i]`, mỗi phần tử chunk trỏ tới mảng `FUObjectItem` **stride 24 byte**, item[0] = `UObject*`.
- 65536 object / chunk (`dword_26310 = 16` bit).
- `UObject::ClassPrivate` ở +0x10, `UObject::NamePrivate` (+0x18) đọc qua GNames.
- Số phần tử lấy từ `*(uint32*)(arr + dword_26318)` (offset này cũng được dò, không hard-code).

### 3.5 Dò offset khi game update (sub_EE3C) — điểm đáng giá nhất
Thay vì hard-code, menu gốc **brute-force** tổ hợp `(0x10/0x18/0x20, 0x10/0x18/0x20, 8/16/24, 16/24, 16/32)`
rồi chấm điểm: với mỗi tổ hợp, nó đi qua ~0xC0 object, đọc tên lớp qua GNames, và cộng điểm nếu tên
trông giống tên lớp thật (`sub_11AD8`) và lớp cha cũng đọc được; cộng thêm điểm nếu tên thuộc danh sách
8 lớp "mỏ neo" (`off_1F360`). Tổ hợp điểm cao nhất được chốt vào `dword_26300/26304/26308/2630C/26310`.

→ Đây là lý do menu sống sót qua các bản update; bản clone của ta dùng đúng ý tưởng nhưng rút gọn
(chấm điểm bằng số object đọc được tên hợp lệ).

### 3.6 Gọi setter (sub_102C8) — chỗ quyết định
```
X0 = object (component)
X1 = UFunction* (setter tìm theo tên)
X2 = &paramBlock   (int đầu tiên = skin id)
```
Bên trong: `fn->FunctionFlags |= 0x400` (FUNC_Native), lấy con trỏ native từ bảng hàm của UFunction
(`8 * dword_263C0`), **kiểm tra con trỏ đó nằm trong vùng `__TEXT` của host**, rồi gọi `fn(obj, params)`,
sau đó phục hồi cờ.

→ Bản clone làm y hệt: chỉ gọi khi con trỏ native nằm trong `__TEXT`, tham số là buffer 64 byte zero
với `int` đầu tiên = skin id.

### 3.7 Áp skin cho đúng khẩu súng đang cầm (`-[PxUE4 applySkin:]`)
- `sub_FE68` (refreshData): quét toàn bộ object, lọc theo lớp, gom danh sách ID skin hợp lệ vào `NSMutableArray`.
- `sub_10484`: từ vị trí camera, chọn object gần nhất trong bán kính **150.0** đơn vị (game unit) → chính là
  khẩu đang cầm/đang ngắm.
- Sau đó `applySkin` chạy 3 nhánh: descriptor → `ModularWeaponDataComponentAppearance` →
  `ModularWeaponFuncComponentAppearance`, trả mã `1 | 2 | 4`; log tương ứng "applied via …".
- Có cache `CACurrentMediaTime()` và cooldown (`dword_26470 > 6` → thôi quét, quét lại sau 1.5 s).

---

## 4. Né anti-cheat: cái gì thật, cái gì không

Đã kiểm tra (evidence):
- Game ship kèm `anogs.framework` (Tencent ACE) + `DataDomeSDK` + `CrashSight*.framework` + `TDMASA/TDMIDFA`.
  ACE là thằng quyết định ban; DataDome lo anti-bot/phía server; CrashSight chỉ báo crash.
- Import table của `PxExtFFi` có: `ptrace`, `sysctl`, `sysctlbyname`, `_dyld_get_image_name`, `dlopen`, `dlsym`,
  `mprotect`, `mach_vm_protect`. **Import ≠ đang dùng**; nhưng tổ hợp này khớp với: tự kiểm tra debugger,
  tự liệt kê image, tự mprotect để inline-hook.
- Không có link tới Substrate/fishhook/ShadowHook ⇒ hook (nếu có) là inline hook tự viết.
- `PxMenu.dylib` **không** import `ptrace/sysctl/dlopen` ⇒ phần UI/skin hoàn toàn không đụng anti-cheat.

Kết luận có cơ sở: **chức năng skin không cần né anti-cheat gì cả** — nó chỉ đọc object UE và gọi setter
client-side. Rủi ro ban đến từ (a) việc app bị chỉnh sửa/ ký lại, (b) Frida/substrate/artefact jailbreak,
(c) patch lung tung vào code ACE. Không phải từ việc đổi skin.

Vì vậy "nâng cấp antiban" trong bản clone = **giảm bề mặt bị phát hiện**, không phải thêm trick:

1. Không swizzle, không inline hook, không patch ACE/anogs — bản clone chỉ đọc bộ nhớ và gọi hàm có sẵn.
2. Từ chối khởi động nếu thấy Frida (`dlopen /usr/lib/frida/frida-agent.dylib`, env `FRIDA_AGENT_PATH`)
   hoặc đang bị trace (`sysctl.proc_traced`) → ngủ im.
3. Không tạo file trong `/var/mobile`, không dùng suite riêng dễ nhận diện; cấu hình chỉ trong NSUserDefaults của app.
4. Jitter khởi động 1.4–2.3 s (timer cố định là fingerprint).
5. Chuỗi tên lớp UE (`ModularWeaponDesc`, `SetSkin…`) và tên export ACE (`AnoSDKGetReportData…`)
   được XOR trong binary → quét chuỗi không thấy. Lưu ý đã gặp: ở `-O2` clang **hằng số hoá**
   vòng XOR và nhét lại chuỗi plaintext vào binary (kiểm tra bằng cách tìm byte trên
   `build_out/DeltaSkin.dylib`). Đã sửa bằng `volatile` salt + `noinline` trong `DSDecode`.
6. Không gọi `ptrace(PT_DENY_ATTACH)` (dấu hiệu tweak kinh điển mà ACE tìm).

Những gì **không** làm được và phải nói thật: không thể đảm bảo "không bao giờ bị ban". Nếu ACE/DataDome
xác thực phía server (ví dụ server gửi skin id và client render khác đi), hoặc nếu họ so hash binary app,
thì mọi bản sửa client đều có rủi ro. Mod skin client-side thuần hiển thị là mức rủi ro thấp nhất trong
tất cả các loại mod.

---

### 4.1 Ai thực sự ban? (phân tích `anogs.framework` = Tencent ACE)

Đã chạy IDA 9.1 headless trên `anogs` (2.9 MB), dump 29 entry `AnoSDK*`, 374 import và
decompile các hàm quanh chuỗi `ban/cheat/report/risk`.

Kết luận có bằng chứng: **không có hàm ban nào trên máy.** Kiến trúc thật là:

```
detector trong anogs  ->  gom bằng chứng vào blob
      -> game gọi AnoSDKGetReportData*()  (import trong binary DeltaForceClient,
         thấy rõ chuỗi "AnoSDKGetReportData" tại 0x17e7c31a / 0x182fb1a4)
      -> game tự upload
      -> server ACE quyết định ban
```

Decompile 3 getter (rút gọn):

```c
AnoSDKGetReportData3()          -> ioctl cmd 37 (0x25) rồi trả con trỏ blob
AnoSDKGetReportData4(int tipo)  -> ioctl cmd 59 (0x3B) rồi trả con trỏ blob
AnoSDKGetReportData / 2         -> BR X9 (nhảy qua bảng dispatch nội bộ)
```

Bốn getter này **không có caller nào bên trong anogs** (xref rỗng) — nghĩa là chỉ host app gọi.
Đó chính là "hàm chịu trách nhiệm ban" ở phía client, và là điểm chặn sạch nhất.

Ba bộ thu thập đáng chú ý:

| Hàm | Việc |
|---|---|
| `sub_4B240` (`cheat_open_id`) | ghi openid của tài khoản vào report, chống đổi acc sau ban |
| `sub_F8B50` (`shell_report`) | report fingerprint thiết bị, bật/tắt theo config, lấy mẫu `rand()%1000==722` (~0.1%) |
| `sub_82230` (`DoRiskFileTCJTask`) | quét file rủi ro theo path |

Và đường doạ người chơi trên máy jailbreak:
`sub_B5420` dựng hộp thoại *"Your device has been jailbroken... EXIT"*, được gọi từ `sub_B53C0`.
Trên iOS 14.8.1 đây là thứ chặn game, không phải ban.

### 4.2 Hook đã cài trong bản clone

`DeltaSkin.mm` mục `ACE (anogs) neutralise`:

```c
ds_install_ace()      // 7 hàm: AnoSDKGetReportData{,,2,3,4} + AnoSDKDelReportData{,3,4}
ds_kill_jb_warning()  // chỉ chạy khi thấy dấu hiệu jailbreak
```

- Ghi đè **prologue 8 byte** thành `mov w0,#0 ; ret` (`0x52800000`, `0xD65F03C0`).
  Không trampoline, không PAC, chạy giống nhau trên arm64 và arm64e.
- `vm_protect(..., VM_PROT_READ|WRITE|COPY)` để lấy bản COW, ghi, `sys_icache_invalidate`,
  rồi trả page về `R|X`. Không để page nào vừa W vừa X.
- Hàm JB được tìm **theo chuỗi** (XOR 0x2B) chứ không theo offset: quét `__TEXT` của `anogs`,
  tìm cặp `ADRP+ADD` trỏ tới chuỗi, lùi về `stp x29,x30` gần nhất trong 0x200 byte.
  Không khớp -> không patch (fail closed, không crash).
- Gọi trong `ds_start()` trước khi UI lên; trạng thái hiện `ace N/7` trong panel.

Vì sao patch prologue chứ không redirect GOT của app: trên arm64e (A12+) các slot
`__auth_got` được ký PAC theo địa chỉ, ghi đè thô sẽ crash; patch code không dính PAC.

### 4.3 Giới hạn phải biết

1. Bản clone **không thể** chặn ban nếu server đã có dữ liệu từ trước, hoặc nếu ban dựa trên
   hash binary / dylib lạ trong bundle. Nó chỉ cắt đường *gửi bằng chứng mới*.
2. Nếu ACE re-checksum đúng page chứa getter, có thể lộ. Ta chỉ sửa 8 byte/hàm và giữ page ở RX.
3. Trên iOS 18 không jailbreak, page `__TEXT` sửa bằng COW vẫn có thể bị `cs_invalid_page`
   nếu bị page-out rồi page-in lại. Chưa quan sát được (không có máy).
4. Code patch JB-dialog chỉ chạy khi `ds_jb_hint()` thấy `/var/jb`, `Cydia.app` hoặc `sshd`
   — trên iOS 18 sạch sẽ không đụng vào.

---

## 5. Sản phẩm: `D:\dfgpt\DeltaSkinMod`

Cấu trúc:

```
DeltaSkinMod\
  src\DeltaSkin.mm          toàn bộ logic (discovery + skin + UI + antiban), ObjC++ một file
  Makefile                  build bằng xcrun clang (macOS)
  .github\workflows\build.yml   build tự động trên GitHub (macOS runner) + artifact
  tools\inject_ipa.sh       chèn dylib vào IPA rồi ký lại (macOS)
  README.md                 hướng dẫn cài trên 2 máy
  REPORT.md                 file này
```

Thiết kế clone (khớp hành vi gốc, bỏ hết phần thừa):

| Thành phần gốc | Trong clone |
|---|---|
| `sub_ED64` quét vm_region | `ds_collect_ranges()` |
| `scanIfNeeded` tìm host/__DATA | `ds_locate_host()` |
| tìm GNames bằng "None" | `ds_find_gnames()` (cùng magic 0x6F4E0008) |
| tìm GObjects chunk 24B/65536 | `ds_find_gobjects()` + `ds_object_at()` |
| dò offset `sub_EE3C` | chấm điểm rút gọn trong `ds_find_gobjects()` |
| `sub_F318` tìm UClass theo tên | `ds_find_class()` |
| `sub_F47C` tìm UFunction theo tên | `ds_find_function()` (lọc theo Outer = UClass) |
| `sub_102C8` gọi setter | `ds_apply_skin()` (validate con trỏ trong `__TEXT`, param = int skinId) |
| menu `PxMenuView` | `DSMenu` (nút nổi "DS" + panel, UITextField nhập ID, Apply/Restore) |

Khác biệt có chủ ý:
- Không có ESP/aimbot/whatever khác.
- Không có bước chọn "khẩu gần camera nhất": bản clone áp cho **mọi** object thuộc 2 lớp weapon desc.
  Nếu thấy lag hoặc áp nhầm, bật lại bộ lọc 150 unit (đã ghi TODO trong code) sau khi có offset transform.
- `ds_func_entry()` dò offset con trỏ native trong khoảng 0x80–0x180 thay vì dùng `dword_263C0` học được
  từ binary (offset đó có thể đổi theo bản build).

---

## 6. Chưa xác minh (phải nói rõ)

1. **Chưa chạy trên thiết bị thật.** Không có máy iOS trong phiên này; mọi kết luận runtime là suy ra từ
   pseudocode + cấu trúc dữ liệu, chưa phải quan sát.
2. Chưa xác định được tên UFunction thực tế tồn tại trên lớp nào (`SetSkin` có thể nằm trên descriptor, không
   phải trên weapon desc). Clone thử lần lượt 4 tên và trả mã lỗi thay vì crash, nhưng đúng/sai chỉ biết khi chạy.
3. Chưa xác định offset `UStruct::Children` / `FProperty` để ghi trực tiếp skin id mà không cần gọi hàm.
4. Chưa kiểm tra được `anogs` phản ứng gì khi app bị re-sign (không có môi trường).
5. Chưa build thử: máy này là Windows, không có Xcode. Dùng GitHub Actions (đã cấu hình) để build.

---

## 7. Build & phát hành

- Repo: https://github.com/LuongLeTanTuan/DeltaSkin (public).
- Máy này không có Xcode; **macOS runner của GitHub Actions bị account này từ chối** (run bị cancel ngay,
  0 bước). Đã xác minh: runner `ubuntu-latest` chạy bình thường.
- Vì vậy workflow build bằng Linux: cài `clang + lld`, tải iPhoneOS SDK từ `theos/sdks`, biên dịch
  `-target arm64-apple-ios14.0`, link bằng `ld64.lld` với `-undefined dynamic_lookup`.
- Lỗi lần đầu đã gặp và đã sửa (ghi lại để khỏi mất công): `mach_vm.h` không tồn tại trên SDK di động →
  dùng `vm_region_recurse_64`; `_dyld_get_image_header` trả `mach_header*` → phải ép kiểu; file nguồn
  phải thuần ASCII (ký tự `—` làm clang báo `unexpected character U+FFFD`).
- Tải bản build: tab **Actions** → run mới nhất → artifact `DeltaSkin-dylib`.

---

## 8. Bước tiếp theo nếu có thiết bị

1. Build dylib (Actions), chèn vào IPA bằng eSign, cài.
2. Mở game, bấm nút "DS" → xem dòng trạng thái. Nếu `GNames not found` / `GObjects not found` thì bản build
   game đã đổi layout → gửi log (Xcode/Console: `[DeltaSkin]`) để chỉnh magic/scan.
3. Nhập skin id → APPLY. Nếu trả `no target matched (code -4)` nghĩa là tên setter không khớp → cần dump
   thêm danh sách UFunction của 3 lớp đó (script IDA đã có trong `D:\dfgpt\work\dump_ida.py`).
4. Nếu crash khi APPLY: con trỏ native dò sai offset (0xE8 thường đúng với UE5.3+). Thử bật cờ
   "safe mode" (chưa viết) hoặc gửi crash log.
