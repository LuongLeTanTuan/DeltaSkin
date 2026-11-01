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

### 3.8 Bảng súng/skin của menu gốc (đã trích ra)

Toàn bộ danh sách trong menu gốc là dữ liệu tĩnh trong `__DATA_CONST`, không phải gọi game:

| Địa chỉ (file = vmaddr) | Nội dung |
|---|---|
| `0x1C2C8` | mảng 85 con trỏ → tên súng (`M4A1 Assault Rifle`, `AKM Assault Rifle`, …) |
| `0x1C680` | 705 dòng, stride 16: `{ int32 weaponId; int32 skinId; char* skinName; }` |

Đọc bằng cách map vmaddr → file offset (trong dylib này `__TEXT` bắt đầu ở 0 nên vmaddr = offset),
resolve con trỏ tên, decode UTF-8. Kết quả: **85 súng / 705 skin, 0 dòng hỏng**, tên tiếng Việt đúng
dấu (bảng gốc lưu UTF-8).

Ba hàm dùng bảng này:

- `sub_77A8(store, weaponId)` — đếm số dòng cùng `weaponId` rồi dựng mảng tên skin; hết tên thì
  fallback `Skin #%u`, danh sách rỗng thì `Default / None`.
- `sub_7948` — chọn súng: lưu `skin_weapon_idx`, nạp lại options của dropdown skin, chọn index 0,
  và đặt `skin_gun_id` = skinId của dòng đầu tiên khớp (`"0x%08X"`).
- `sub_7AD0` — chọn skin thứ N: đặt `skin_gun_id` theo dòng khớp thứ N.
- `sub_7BA4` — đọc `skin_gun_id`, `strtoul(...,0,0)`, gọi `-[PxUE4 applySkin:]`, map mã trả về ra
  câu thông báo "applied via …".

Bản clone đầu tiên nhúng nguyên bảng này vào `src/SkinTable.h` dưới dạng blob XOR `0x5A` (85 tên súng +
705 dòng). Bảng đó đã bị thay — lý do ở 3.9.

### 3.9 Phải lấy lại bảng từ `PxExtFFi` (64 súng / 705 skin) — vì sao bảng cũ lệch

Bảng ở 3.8 đọc **đúng** nhưng **chia nhóm sai**, và đó chính là triệu chứng "danh sách skin bị lệch,
bấm ô này ra ô khác".

`sub_77A8` nhóm theo `weaponId` (int32) trong bảng. Nhưng trong bảng của `PxMenu.dylib`, 22 trong 85
`weaponId` thực chất là **id riêng của một skin** — tên súng tương ứng đọc ra là
`ASh-12 Battle Rifle-Goose Goose Duck`, `KC17 Assault Rifle-SAW`… Tức cột trái hiện một *skin* như thể nó
là một *khẩu súng*, và bấm vào đó thì cột phải chỉ có đúng một dòng. Các dòng thật của khẩu đó vẫn nằm ở
nhóm gốc, nên danh sách vừa thiếu vừa lệch — lỗi dữ liệu, không phải lỗi vẽ.

`PxExtFFi` (framework UI của chính menu bên bán) lưu mỗi skin kèm **cả** id **và** chuỗi hiển thị đầy đủ
`"Súng - Skin"`:

| Địa chỉ | Nội dung |
|---|---|
| `0x1CF05A8` | dòng weapon skin, 690 bản ghi |
| `0x1CF46A0` | dòng melee / cosmetic, 18 bản ghi |

Mỗi dòng là 16 byte `{ u32 id; u32 kind=6; u32 nameFileOff; u32 nameTag=0x00300000 }`. Khoảng cách giữa
hai dòng **không cố định** (16 ở catalog đầu, 24 ở catalog thứ hai), nên chỉ đọc được bằng cách quét cặp
`(kind, nameTag)` rồi giải mã con trỏ tên.

**Lỗi thật của bảng cũ.** Bảng 78/707 trước đây sinh ra bằng cách quét 4 byte thô trên toàn file. Cách đó
khớp thêm **3 bản ghi ma** nằm ngoài chuỗi thật, cả ba cùng trỏ vào một offset tên chết `0x1CC46B1`:

| Offset bản ghi | id ma | Chỗ nó bị gán nhầm trong bảng cũ |
|---|---|---|
| `0x1CF2528` | `0x86231595` | `SV-98 Sniper Rifle` → "Khéo Léo" |
| `0x1CF2B28` | `0x862C3D54` | `Cung Phức Hợp` → "Một Lòng Tĩnh Lặng" |
| `0x1CF3248` | `0x86BBAC15` | `SAW` |

Ba id đó **không tồn tại** trong catalog của nhà bán. Chọn đúng dòng đó thì game nhận một appearance id
không có thật và rơi về skin mặc định (hoặc skin của khẩu khác) — đúng kiểu "id tùm lùm".

Bảng mới do `tools\build_table.py` sinh tất định từ `PxExtFFi`:

- Bỏ mọi bản ghi có con trỏ tên không giải được → còn **705 bản ghi** (khớp tuyệt đối với 705 dòng của
  `PxMenu.dylib` đọc độc lập ở `0x1C680`).
- Chia nhóm theo chính chuỗi `"Súng - Skin"` của nhà bán. 8 chuỗi dán liền dấu gạch (`KC17 Assault
  Rifle-SAW`) được tách lại vào đúng khẩu cha bằng cách so tiền tố với danh sách súng đã biết.
- 18 mục melee / cosmetic không có tiền tố súng gom vào một nhóm `Cận chiến & Khác` thay vì hiện thành
  18 khẩu súng giả.

Kết quả: **64 nhóm, 705 dòng, 705 id khác nhau**. `tools\verify_table.py` dựng lại đúng `ds_load_table()`
trên header và đối chiếu từng id với catalog nhà bán:

```
consumed 18352/18352 blob bytes
64 weapon groups / 705 skin rows / 705 unique ids
vendor catalog: 705 ids (3 ghost records dropped)
table ids == vendor ids: True
```

Định dạng blob trong `src/SkinTable.h`: 64 tên súng length-prefixed, rồi 705 dòng
`{ u8 weaponIndex, u32 skinId, u8 nameLen, name }`, XOR `0x5A` (rồi XOR thêm `gMaskSalt`). `ds_load_table()`
chỉ đọc — nó **không** suy luận nhóm lúc chạy, nên không còn đường nào để UI lệch khỏi bảng: cặp
(`weaponIdx`, `skinIdx`) là nguồn duy nhất, và `ds_skin_id()` tra trong đúng nhóm đó.

> Nhóm `Cận chiến & Khác` là dữ liệu thật của nhà bán nhưng menu này **chỉ gọi setter trên
> `ModularWeaponDesc`**, nên id melee áp vào súng sẽ không ra đúng skin. Menu gốc có nhánh riêng cho
> melee ("Switch to melee weapon to apply", `0x1CCF7BD`).

### 3.10 Tên setter: bảng cũ có hai tên không tồn tại

`ds_setter_rank()` xếp hạng theo tên UFunction. Bảng tên cũ lấy từ chuỗi trong `PxMenu.dylib`, nhưng
kiểm lại trên binary game thì:

| Tên | Có trong `DeltaForceClient`? |
|---|---|
| `SetSkinId` | **không** — 0 lần |
| `SetSkinApperanceId` | có |
| `SetSkinInfo` | có (11 lần) |
| `SetSkin` | có |
| `SetSkin_BS` / `SetSkin_ES` | có |
| `ApplySkin` | có (17 lần) |

`SetSkinId` nằm ở hạng cao nhất nên mỗi lần phân giải đều quét hết bảng object rồi không khớp gì; còn
`SetSkinInfo` thì chưa bao giờ được thử. Thứ hạng mới: `SetSkinApperanceId` (nhận thẳng một `int` id, đúng
cái được ghi vào param block) → `SetSkinInfo` → `SetSkin` → `ApplySkin` → `SetSkin_BS`/`SetSkin_ES`.

Vẫn còn một khoảng cách chưa vá: menu gốc leo thang bốn bước — descriptor → `…DataComponentAppearance` →
`…FuncComponentAppearance` → "all components"; bản clone **chỉ** gọi descriptor. Đó là lý do có khẩu skin
không hiện. Chưa sửa vì chưa có máy để thử.

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

1. Không swizzle, không inline hook, không patch logic game. Chỗ duy nhất bị sửa code là 7 hàm
   *gửi report* của ACE (`AnoSDKGetReportData*` / `AnoSDKDelReportData*`) — xem 4.1/4.2.
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
  src\SkinTable.h           bảng 64 súng / 705 skin, XOR 0x5A, 18 352 byte
  patcher\macho.c           đọc/sửa/ký lại Mach-O (struct riêng, không phụ thuộc SDK)
  patcher\sha256.c          SHA-256 tự viết (CI chạy được trên Linux lẫn iOS)
  patcher\main.m            app DeltaSkin: tìm game, backup, Patch, Restore
  patcher\entitlements.plist  platform-application + no-sandbox
  tools\patcher_cli.c       bản CLI của cùng engine, dùng trong CI
  tools\verify_sig.py       verifier độc lập (đọc lại chữ ký, băm lại từng page)
  Makefile                  build bằng xcrun clang (macOS)
  .github\workflows\build.yml   build tự động trên GitHub (ubuntu) + 2 artifact
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
| menu `PxMenuView` | `DSMenu` — nút nổi "DS" gắn vào window của game, panel trong window riêng, **hai `UITableView` cạnh nhau** Súng → Skin (xem 5.1) |

Khác biệt có chủ ý:
- Không có ESP/aimbot/whatever khác.
- Không có bước chọn "khẩu gần camera nhất": bản clone áp cho **mọi** object thuộc 2 lớp weapon desc.
  Nếu thấy lag hoặc áp nhầm, bật lại bộ lọc 150 unit (đã ghi TODO trong code) sau khi có offset transform.
- `ds_func_entry()` dò offset con trỏ native trong khoảng 0x80–0x180 thay vì dùng `dword_263C0` học được
  từ binary (offset đó có thể đổi theo bản build).

### 5.1 Chọn skin: clone từ bản no-JB + fix "tắt menu xong không bấm được gì"

Bản đầu của clone dùng `UISegmentedControl` + `UIPickerView`. Nó sai ở hai chỗ, và cả hai đều là lỗi
**luồng chọn** chứ không phải lỗi hiển thị:

1. **Picker là danh sách phẳng, menu gốc là hai danh sách lọc nhau.** Tab `SKIN` phải là "skin của khẩu
   đang chọn", nhưng picker giữ `skinIdx` cũ khi đổi súng, nên `ds_skin_id()` trả về dòng của khẩu
   *trước* → apply ra skin sai hoặc ra `0` (`no target matched`).
2. **Picker không có nút xác nhận.** `valueChanged` bắn liên tục trong lúc cuộn, nên mỗi lần lướt qua
   một dòng là một lần đổi `skinIdx`, không có mốc "chốt".

Cách chọn giờ clone từ `D:\delta\PxExtNoJB` (`Menu\PxMenuView.m`), nhưng đổi cấu trúc: bản gốc dùng hai
combo bật ActionSheet, ở đây là **hai bảng cạnh nhau** — vì trên màn hình game, mở ActionSheet là mất luôn
ngữ cảnh "đang chọn khẩu nào", còn hai cột thì thấy cả hai cùng lúc:

| Gốc | Clone |
|---|---|
| panel xếp dọc, chọn súng rồi mở bảng skin | `weaponTable` (trái) + `skinTable` (phải), hai `UITableView` cạnh nhau, hai data source riêng |
| chọn súng → reset skin về index 0 | `tableView:didSelectRowAtIndexPath:` cột trái → `skinIdx = 0` + `[skinTable reloadData]` |
| ô nhập ID tự do trong panel | **bỏ hẳn.** Nhãn `0x…` chỉ đọc, luôn lấy từ `ds_skin_id()` theo đúng cặp (khẩu, skin) đang chọn |
| `comboTapped:` → `UIAlertController` ActionSheet | không dùng cho danh sách; ActionSheet chỉ còn cho xác nhận |
| `PxToast` = `UIAlertController` Alert | `ds_toast()` — cùng cách, ưu tiên window của menu nếu đang mở |

Bỏ ô nhập ID là fix cho đúng triệu chứng "chọn ô này ra id khác": trước đây ID đến từ ba nguồn (ô nhập,
`skinIdx`, và dòng vừa bấm) và ba nguồn đó lệch nhau sau khi đổi súng. Giờ chỉ còn **một** nguồn: cặp
(`weaponIdx`, `skinIdx`) đang được highlight, và ID được tra từ bảng theo cặp đó tại thời điểm bấm Apply.

**Lỗi "mở menu rồi tắt thì màn hình ngoài không thao tác được"** — nguyên nhân nằm ở bản clone cũ, không
phải ở game:

```objc
// bản cũ
self.root = [[UIView alloc] initWithFrame:UIScreen.mainScreen.bounds];
self.root.backgroundColor = UIColor.clearColor;
self.root.userInteractionEnabled = YES;   // <-- đây
[host addSubview:self.root];
...
- (void)close { self.panel.hidden = YES; }   // <-- và đây
```

`self.root` phủ **toàn màn hình**, trong suốt, nhưng `userInteractionEnabled = YES`. Hit-testing của
UIKit không quan tâm view đó có màu gì: nó vẫn là view trên cùng của window game, nên mọi cú chạm đều
rơi vào `root` và bị nuốt. `panel.hidden = YES` chỉ ẩn panel con — `root` vẫn ở đó, vẫn nhận chạm.
Đây là cùng một lỗi kinh điển của overlay trong suốt.

Bản mới bỏ hẳn `root`:

- Nút **DS** là một `UIButton` 52×52 thêm thẳng vào window của game — chỉ 52×52 điểm đó nhận chạm.
- Panel nằm trong `UIWindow` **riêng** (`windowLevel = UIWindowLevelAlert + 60`) chỉ tồn tại lúc menu mở.
- `hide` làm ba việc, không chỉ `hidden = YES`:

```objc
[self.panel removeFromSuperview];              // panel được giữ lại, window thì không
w.rootViewController.view.userInteractionEnabled = NO;
w.hidden = YES;
w.windowScene = nil;                            // iOS 13+: tháo khỏi scene, không chỉ ẩn
UIWindow *target = ds_host_window();            // trả key window về cho game
if (target) [target makeKeyWindow];
```

`windowScene = nil` là điểm quan trọng: một `UIWindow` chỉ `hidden = YES` vẫn nằm trong
`UIApplication.windows`, vẫn có thể giữ key status, và trên iOS 13+ vẫn tham gia scene — đó là nửa còn
lại của triệu chứng "bấm không ăn". `ds_host_window()` chọn window **thấp nhất còn hiển thị** dưới
`UIWindowLevelAlert`, nên không bao giờ trả về chính window của menu.

Nút **DS** cũng được phân biệt tap với kéo bằng cờ `dragging` (đặt ở `UIGestureRecognizerStateBegan`,
tiêu thụ ở `fabTapped`) — bản gốc `PxMenuView` dùng đúng cách này; kiểm tra `pan.state` lúc
`TouchUpInside` không đáng tin vì pan đã về `Ended` trước khi tap bắn.

---

## 6. Đường iOS 14: app patcher (TIPA) và chuyện ký lại Mach-O

Máy iOS 14 chạy TrollStore không có máy tính bên cạnh, nên không thể "chèn dylib vào IPA rồi ký bằng eSign".
Cách duy nhất không cần PC: **một app thứ hai** được TrollStore cài, tự mở file thực thi của game ra sửa.
Đó là toàn bộ lý do `patcher\` tồn tại — nó không phải bản mod của game, nó là cái tuốc-nơ-vít.

### 6.1 Ground truth: chữ ký của chính game

Mọi thứ trong `patcher\macho.c` được viết lại từ **chữ ký có thật** trong `DeltaForceClient`, không phải từ
tài liệu (tài liệu Apple về `CodeDirectory` công khai nhưng thiếu đúng mấy chỗ cần thiết). Đọc trực tiếp:

| Trường | Giá trị đo được |
|---|---|
| `LC_CODE_SIGNATURE` | `dataoff = 0x1830AB70`, `datasize = 0x9D8B40` (10 324 800) |
| magic SuperBlob | `fa de 0c c0` — tức `0xfade0cc0` **big-endian** |
| CodeDirectory | version `0x20400`, flags `0x0`, `hashOff 342`, `identOff 88`, `nSpecial 7`, `nCode 99083` |
| `codeLimit` | `0x1830AB70` = đúng `dataoff` (byte đầu tiên **không** được băm) |
| hash | SHA-256 (`hashType 2`), `pageShift` **12** → page 4 KiB |
| identifier | `com.garena.game.df` |
| execSeg | `execBase 0`, `execLimit 0x1380C000`, `execFlags 0x11` |
| blob trong SuperBlob | `0` CD, `2` requirements, `5` entitlements (`fade7171`), `7` DER entitlements, `0x10000` CMS (`fade0b01`, 4428 byte) |

Ba điều rút ra, cả ba đều là thứ mà một implementation "theo trí nhớ" sẽ làm sai:

1. **Toàn bộ cấu trúc chữ ký nằm big-endian**, trong khi mọi trường khác của Mach-O là little-endian.
   `macho.c` vì thế có `cd_put`/`cd_put64` ghi tay từng byte, không `memcpy` struct.
2. **`pageShift` là 12, không phải 14.** Nhiều bài viết nói arm64 iOS dùng page 16 KiB; bản build này dùng
   4 KiB. Sai chỗ này thì `nCode` lệch 4 lần và mọi hash đều sai — mà lại *không* báo lỗi rõ ràng, chỉ là
   app không mở.
3. `execLimit` = `0x1380C000` = `__TEXT` `filesize`, và `execBase` = `0` = `fileoff`. Không phải `vmaddr`
   (`0x100000000` không nhét vừa `uint32`). Đây là chỗ dễ sai thứ ba.

### 6.2 Sáu lỗi đã gặp thật, và cách sửa

Ghi lại vì mỗi lỗi đều tốn một vòng CI:

| Triệu chứng | Nguyên nhân | Sửa |
|---|---|---|
| verifier báo `bad SuperBlob magic` | ghi little-endian | `cd_put` ghi tay big-endian |
| `page 0 mismatch` (chỉ page 0) | `LC_CODE_SIGNATURE` + `__LINKEDIT` được ghi **sau** khi băm page | ghi hết header trước, băm sau |
| `signature does not fit in the reserved headroom` | đo kích thước bằng "2 page + 0x4000" — file 400 MB cần ~800 KB riêng cho bảng hash (24 700 slot) | `sig_measure()` đo đúng một lần, dùng lại |
| entitlements đọc ra rỗng | ghi XML trần, không có header blob | đóng gói `0xfade7171` + len + XML |
| `execSegLimit` sai | lấy `vmsize` của `__TEXT` | lấy `fileoff`/`filesize` |
| tốn 800 MB RAM | `read_file` rồi `realloc` — copy cả file 400 MB hai lần | một `calloc(n + 4 MB)`, tail là zero page của kernel |

Sửa cuối là bắt buộc trên máy thật: iOS 14.8.1 trên máy 3 GB RAM sẽ bị jetsam giết trước khi patch xong nếu
copy file hai lần.

### 6.3 Chiến lược ký: ad-hoc + mang theo CMS cũ

`patcher` **không** ký bằng chứng chỉ (không có, và TrollStore không cần). Nó làm đúng hai việc:

- CodeDirectory mới: `flags = 0` khi có CMS (không đặt `CS_ADHOC`, vì blob đã có chữ ký thật),
  `flags = 2` (`CS_ADHOC`) khi file không có CMS. `execFlags = MAIN_BINARY | ALLOW_UNSIGNED`.
- Blob `0x10000` (CMS) của chữ ký **cũ được chép nguyên byte** sang chữ ký mới. Không băm lại, không kiểm
  tra — CodeDirectory ở trên mới là thứ quyết định hash từng page.

Lý do: trên iOS 14, đường mà TrollStore đi qua là CoreTrust. CoreTrust không chấp nhận một CodeDirectory
ad-hoc trần cho app đã cài; nó chấp nhận app mà nó đã "tin" từ trước. Giữ CMS cũ không làm chữ ký *đúng*
hơn, nhưng giữ app ở đúng trạng thái nó đang ở trước khi patch, thay vì tệ hơn.

Cái **đã chứng minh** (chạy được, có log): `tools\verify_sig.py` là verifier viết độc lập, không dùng code
của patcher — nó đọc lại `LC_CODE_SIGNATURE`, parse SuperBlob, băm lại từng page từ đĩa và so với slot.
Trên `DeltaSkinPatcher` trong TIPA: `OK 22/22 page hashes verified`, entitlements 685 byte, slot `-1` khớp.
Cùng verifier đó chạy trên chữ ký gốc của game để đối chiếu (nếu nó báo sai chữ ký của Apple thì verifier
sai, không phải patcher sai).

Cái **chưa chứng minh**: CoreTrust/TrollStore trên máy thật có chấp nhận bản đã ký lại hay không. Không có
thiết bị iOS trong phiên này. Xem 6.5.

### 6.4 Patch làm gì, theo đúng thứ tự

1. Tìm app: quét `/var/Containers/Bundle/Application/*` (và `/private/var/...`), xác nhận bằng
   `CFBundleIdentifier = com.garena.game.df` (khớp chính xác, so trước), rồi mới tới `CFBundleExecutable =
   DeltaForceClient` và các biến thể `*deltaforce*` / `*deltawar*`. Không đoán theo đường dẫn cứng.
   - Đối chiếu bản build đang có: bundle id `com.garena.game.df`, exe `DeltaForceClient`, tên hiển thị
     `Garena Delta Force`, version `1.203.37117`, `MinimumOSVersion 10.0`.
2. Backup **một lần**: `DeltaForceClient` (file thực thi) + `Info.plist` → `Documents/backup/<bundle-id>/`
   của app DeltaSkin. Các lần Patch sau dùng lại bản gốc đó, không ghi đè — nên Patch hai lần vẫn Restore
   về đúng bản gốc đầu tiên.
3. Chép `DeltaSkin.dylib` (nằm sẵn trong app) vào `DeltaForceClient.app/Frameworks/`.
4. Chèn `LC_LOAD_DYLIB` = `@executable_path/Frameworks/DeltaSkin.dylib` vào header, rồi ký lại tại chỗ.

Bước 4 có ba cái chặn, tất cả đều **fail closed** (báo lỗi, không ghi gì):
- Không đủ chỗ trong header cho load command → `no header room for LC_LOAD_DYLIB`. Header game có
  `0x768` byte đệm (padding giữa load commands và `__TEXT,__text` ở `0x4000`) nên thực tế là đủ.
- Dylib đã có trong danh sách → trả `-2`, không chèn trùng (so sánh có giới hạn theo `cmdsize`, không
  `strncmp` mù).
- File không phải Mach-O arm64 thuần → `not a thin arm64 Mach-O`.

Entitlements của game và CMS **được đọc từ chính file đang sửa**, không phải từ plist rời — nên không có
chuyện patch một bản game khác mà lại ký bằng entitlements của bản này. `main.m` truyền `ent = NULL` và
`macho.c` tự bóc slot `5` + slot `0x10000` ra trước khi ghi đè.

### 6.5 Chưa xác minh trên máy thật

1. **CoreTrust/TrollStore có nhận bản đã ký lại không.** Đây là rủi ro chính, và là lý do có nút
   **Restore original**.
2. `platform-application` + `com.apple.private.security.no-sandbox` trong `patcher\entitlements.plist` là
   điều kiện để app ghi được vào bundle của app khác. Trên TrollStore thì hai entitlement này thường được
   cho qua; chưa thử.
3. Chưa biết `anogs` (ACE) phản ứng gì với một app có thêm `LC_LOAD_DYLIB` và CodeDirectory mới.
4. Kích thước TIPA: 58 785 byte. Giải nén: `DeltaSkin.dylib` 137 744 + `DeltaSkinPatcher` 89 136 +
   `Info.plist` 1 520.

Nếu Patch xong game không mở: mở lại app DeltaSkin → **Restore original** → game về nguyên trạng (file thực
thi + `Info.plist` + xoá dylib khỏi `Frameworks/`). Bản backup nằm trong `Documents` của app DeltaSkin nên
gỡ app đó là mất luôn đường lùi — restore trước, xoá sau.

---

## 7. Chưa xác minh (phải nói rõ)

Danh sách dưới đây là cho **dylib** (menu + skin). Danh sách cho **app patcher** nằm riêng ở 6.5 — cả hai
đều cùng một lý do: không có máy iOS trong phiên này.

1. **Chưa chạy trên thiết bị thật.** Không có máy iOS trong phiên này; mọi kết luận runtime là suy ra từ
   pseudocode + cấu trúc dữ liệu, chưa phải quan sát.
2. Chưa xác định được tên UFunction thực tế tồn tại trên lớp nào (`SetSkin` có thể nằm trên descriptor, không
   phải trên weapon desc). Clone thử lần lượt 4 tên và trả mã lỗi thay vì crash, nhưng đúng/sai chỉ biết khi chạy.
3. Chưa xác định offset `UStruct::Children` / `FProperty` để ghi trực tiếp skin id mà không cần gọi hàm.
4. Chưa kiểm tra được `anogs` phản ứng gì khi app bị re-sign (không có môi trường).
5. Chưa build thử: máy này là Windows, không có Xcode. Dùng GitHub Actions (đã cấu hình) để build.

---

## 8. Build & phát hành

- Repo: https://github.com/LuongLeTanTuan/DeltaSkin (public).
- Máy này không có Xcode; **macOS runner của GitHub Actions bị account này từ chối** (run bị cancel ngay,
  0 bước). Đã xác minh: runner `ubuntu-latest` chạy bình thường.
- Vì vậy workflow build bằng Linux: cài `clang + lld`, tải iPhoneOS SDK từ `theos/sdks`, biên dịch
  `-target arm64-apple-ios14.0`, link bằng `ld64.lld` với `-undefined dynamic_lookup`.
- Lỗi lần đầu đã gặp và đã sửa (ghi lại để khỏi mất công): `mach_vm.h` không tồn tại trên SDK di động →
  dùng `vm_region_recurse_64`; `_dyld_get_image_header` trả `mach_header*` → phải ép kiểu; file nguồn
  phải thuần ASCII (ký tự `—` làm clang báo `unexpected character U+FFFD`).
- Tải bản build: tab **Actions** → run mới nhất → một run ra **hai** artifact:

  | Artifact | Nội dung | Dùng cho |
  |---|---|---|
  | `DeltaSkin-tipa` | `DeltaSkin.tipa` 58 785 byte = `DeltaSkin.app` (`DeltaSkin.dylib` + `DeltaSkinPatcher` + `Info.plist`) | TrollStore, iOS 14 |
  | `DeltaSkin-dylib` | `DeltaSkin.dylib` 137 744 byte, arm64 | chèn vào IPA bằng eSign/Sideloadly |

- Run đã kiểm tra: https://github.com/LuongLeTanTuan/DeltaSkin/actions/runs/41261986446
  (`DeltaSkin.dylib` nguyên bản: 0 hit cho `AnoSDK`, `SetSkin`, `ModularWeapon`, `jailbroken`,
  `DeltaForceClient`, `GNames/GObjects`, `UObject` **và** 0 hit cho tên súng/skin như `M4A1`,
  `Assault Rifle`, `Submachine`, `Sniper Rifle`).
- Kích thước 87 KB → 137 KB vì có bảng **64 súng / 705 skin** nhúng (blob XOR 18 352 byte) cộng phần UI
  hai cột (hai `UITableView` + Auto Layout dựng lại mỗi lần mở).
- Job `patcher` trong cùng workflow **chạy thật** chứ không chỉ biên dịch: nó build một Mach-O arm64 giả
  (`tools\dummy_main.c`, link với `-headerpad 0x800`), chạy `patcher_cli inject` trên đó, rồi
  `tools\verify_sig.py` băm lại từng page. Đây là thứ đã bắt được lỗi `page 0 mismatch` ở 6.2 — nếu chỉ
  biên dịch thì lỗi đó đi thẳng ra máy người dùng.

---

## 9. Bước tiếp theo nếu có thiết bị

1. **iOS 14 + TrollStore:** cài `DeltaSkin.tipa` → mở app → xác nhận nó tìm ra game → **Patch** → mở game.
   Nếu game không mở được: mở lại app → **Restore original**. Đây là phép thử cho toàn bộ mục 6.
2. **iOS 18 no-JB:** tải `DeltaSkin.dylib`, chèn vào IPA bằng eSign, cài.
3. Mở game, bấm nút **DS** → xem dòng `runtime`. Nếu `GNames not found` / `GObjects not found` thì bản
   build game đã đổi layout → gửi log (Xcode/Console: `[DeltaSkin]`) để chỉnh magic/scan.
4. Chọn súng ở cột trái → chọn skin ở cột phải → **Apply Skin**. Nếu trả `Nothing applied (code -4)` nghĩa
   là tên setter không khớp → cần dump thêm danh sách UFunction của 3 lớp đó (script IDA đã có trong
   `D:\dfgpt\work\dump_ida.py`). Nếu apply ra **sai skin** thì lỗi nằm ở bảng `SkinTable.h`, không ở UI —
   đối chiếu cặp (khẩu, skin) với `PxExtFFi` ở mục 3.
5. Nếu crash khi APPLY: con trỏ native dò sai offset (0xE8 thường đúng với UE5.3+). Thử bật cờ
   "safe mode" (chưa viết) hoặc gửi crash log.
