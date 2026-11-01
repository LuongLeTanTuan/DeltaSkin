# dbpatch — đổi skin bằng cách sửa file dữ liệu, không chèn code

Cách khác hoàn toàn với `DeltaSkin.dylib` ở thư mục gốc. Ở đây **không có dylib, không hook,
không tiến trình thứ hai**. Game tự đọc một file SQLite trong thư mục Documents của nó; ta sửa
nội dung file đó. Anti-cheat không thấy gì ở tầng code vì không có code nào bị chèn.

## Tại sao được

`Documents/DeltaForce/Saved/GameData/DataTable.bytes` là SQLite 3 (12 bảng). Bảng
`WeaponSkinAppearanceTable_CombineTable` có 2942 dòng, mỗi dòng là **blob mô tả ngoại hình**
của một skin: material 1P, material 3P, mesh, các component hiệu ứng, socket, attach mesh.

Chép blob của skin đắt tiền đè lên blob của skin thường → client vẽ skin đắt tiền, server vẫn
thấy skin gốc. Chỉ máy bạn thấy.

Bằng chứng file này là nguồn thật (log `Saved/Logs/DeltaForce.log`, XOR 0x5C):

```
GameCoreDataTable: Display: SQLite CreateCombineDataTable:DataTable
  /Engine/Transient.WeaponSkin/WeaponSkinAppearanceTable_CombineTable_1884707258 bEnableSQLite:1
GameCoreDataTable: Display: [CreateCombineTable] runtime mmap arena for
  '/Engine/Transient.WeaponSkin/WeaponSkinAppearanceTable_CombineTable_1884707258': CREATED, rows=2942
```

Và: xoá file đi rồi mở game, game **tự sinh lại** đúng file đó trong Documents. Nó sở hữu file,
nó đọc file. Không có chuyện đọc thẳng từ pak.

## Cài

Chép `dtskin.py` vào cùng thư mục với `DataTable.bytes`:

```bash
GD=/var/mobile/Containers/Data/Application/<UUID>/Documents/DeltaForce/Saved/GameData
scp dtskin.py root@<ip>:$GD/
```

Cần `python3` trên máy (Taurine có sẵn). Lần chạy đầu tự tạo `DTB_ORIG.bak`.

## Dùng

Phải **thoát game trước** (`killall DeltaForceClient`), sửa xong mở lại.

```bash
cd $GD

python3 dtskin.py list                 # 57 súng, 253 dòng thân súng
python3 dtskin.py list M16A2           # các skin của một súng, * = blob giàu nhất
python3 dtskin.py apply M16A2          # ép mọi dòng thân M16A2 thành skin giàu nhất
python3 dtskin.py apply M16A2 11399    # hoặc chỉ định dòng nguồn
python3 dtskin.py apply-all            # tất cả 57 súng, một lệnh
python3 dtskin.py show 11399           # xem field của một dòng
python3 dtskin.py restore              # trả lại DB gốc
```

`apply-all` chạy ~2 giây, DB phình từ 166 MB lên ~168 MB (blob lớn hơn ghi đè blob nhỏ).
`PRAGMA integrity_check` chạy sau mỗi lần ghi.

## Dòng nào copy được

Chỉ dòng **thân súng**: material nằm dưới `/Models/Weapons/Parts/.../<tên súng>/` và field
`0x46` bắt đầu bằng `EWeaponSkinRareType`. Các dòng `EAdapterItemType::*` (băng đạn, ốp lót,
báng, ốp tay, nòng, kính ngắm, đầu nòng, tay cầm) là slot phụ kiện riêng — chép blob thân súng
vào đó sẽ làm hỏng slot đó. `dtskin.py` tự lọc.

Cùng lý do, `SkinAppearanceId` và uint32 ở offset `0x00` của blob phải ghi lại bằng RowName đích,
nếu không dòng tự khai sai danh tính. Script làm việc đó.

## Hiệu ứng

`SkinComponents` (offset `0xbb` khi dòng có field này) là danh sách class component hiệu ứng
gắn theo skin. Vì ta chép **nguyên blob**, danh sách đó đi theo. `apply` mặc định chọn dòng có
blob lớn nhất — đó là dòng nhiều field nhất, tức nhiều component nhất.

## Đã kiểm chứng / chưa

| Việc | Trạng thái |
|---|---|
| Game đọc `DataTable.bytes` trong Documents | **đã chứng minh** bằng log + xoá file thì game sinh lại |
| DB đã sửa vẫn qua được `DFMDatatableValidator` | **đã chứng minh** — boot sạch, `rows=2942`, không lỗi validator |
| DB đã sửa làm đổi hình súng trong game | **chưa xác nhận bằng mắt** — bước cuối |
| Hiệu ứng (trail, đầu nòng, đạn) đổi theo | **chưa xác nhận** — cùng cơ chế blob, nhưng chưa nhìn |

## Rủi ro

- Sửa DB là sửa dữ liệu client, không đụng tiến trình. Nhưng đây vẫn là sửa file game — dùng
  tài khoản phụ.
- Cập nhật game có thể ghi đè `DataTable.bytes`; lúc đó chạy lại `apply-all`.
- `restore` chỉ chạy được khi `DTB_ORIG.bak` còn. Xoá tay thì mất bản gốc — giữ một bản ở máy tính.
