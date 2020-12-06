# FindCrypt3
Find crypto constants IDA 7.x plugin

Plugin này được phát triển dựa trên findcrypt1 và findcrypt2 của Ilfak của HexRays. 

Bài trên blog về findcryptx origin của HexRays:
1. https://www.hex-rays.com/blog/findcrypt/
2. https://www.hex-rays.com/blog/findcrypt2/

Có tham khảo source code, idea và các consts từ:

1. https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt
2. https://github.com/d3v1l401/FindCrypt-Ghidra

Còn lại, tôi sưu tập, collect các crypto consts (table, sparse_const, nonsparse_const, opcode_const...) từ nhiều nguồn khác nhau:
1. CryptoPP library
https://github.com/weidai11/cryptopp
2. LibTomCrypt
https://github.com/libtom/libtomcrypt
3. ASM CryptoHash of drizz
4. Delphi DCPCrypto Lib

Tạm thời plugin vẫn chưa hoàn thiện, vẫn trong giai đoạn fix lại code và optimize speed. Nhưng đã tạm chạy được.

Các bạn nên dùng thêm 2 plugin sau để scan IDA database khi bắt đầu phân tích:
1. Plugin IDA Signsrch của simabus:
https://sourceforge.net/projects/idasignsrch/

2. Findcrypt Yara:
https://github.com/polymorf/findcrypt-yara 

# TODO:
1. Add chooser show result crypto scan
2. Add menu commant "Crypto consts..." ở Search menu của IDA
3. Scan opcode với opcode_consts
3. Optimize speed tối đa có thể.

Then, bét rì ga :D
