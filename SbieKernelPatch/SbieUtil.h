#pragma once
/*****************************************************************//**
 * \file   SbieUtil.h
 * \brief  Sbie相关函数, 获取HWID, 获取pdb中变量偏移等
 *********************************************************************/
#include <windows.h>
#include <string>

namespace SbieUtil {
    // Sandboxie 原始公钥, 特征码
    static const uint8_t KphpOriginalPublicKey[] = {
        0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
        0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D, 0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
        0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6, 0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
        0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D, 0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
        0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
    };

    // SMBIOS Structure header
    typedef struct _dmi_header {
        UCHAR type;
        UCHAR length;
        USHORT handle;
        UCHAR data[1];
    } dmi_header;

    // Raw SMBIOS data returned by GetSystemFirmwareTable
    typedef struct _RawSMBIOSData {
        UCHAR  Used20CallingMethod;
        UCHAR  SMBIOSMajorVersion;
        UCHAR  SMBIOSMinorVersion;
        UCHAR  DmiRevision;
        DWORD  Length;
        UCHAR  SMBIOSTableData[1];
    } RawSMBIOSData;

    // 将单字节转为 HEX 字符串 (宽字符)
    wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
    {
        static const wchar_t* digits = L"0123456789ABCDEF";
        *ptr++ = digits[b >> 4];
        *ptr++ = digits[b & 0x0F];
        return ptr;
    }

    // 获取固件UUID, 成功返回 TRUE
    BOOL GetFwUuid(UCHAR* uuid)
    {
        BOOL result = FALSE;

        // 第一次调用获取所需缓冲大小
        UINT bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (bufferSize == 0)
            return FALSE;

        BYTE* buffer = (BYTE*)malloc(bufferSize);
        if (!buffer)
            return FALSE;

        if (GetSystemFirmwareTable('RSMB', 0, buffer, bufferSize) != bufferSize) {
            free(buffer);
            return FALSE;
        }

        RawSMBIOSData* smb = (RawSMBIOSData*)buffer;

        for (UCHAR* data = smb->SMBIOSTableData;
            data < smb->SMBIOSTableData + smb->Length;)
        {
            dmi_header* h = (dmi_header*)data;
            if (h->length < 4)
                break;

            // Type 0x01 = System Information
            if (h->type == 0x01 && h->length >= 0x19)
            {
                UCHAR* uuidField = data + 0x08; // UUID ƫ��

                BOOL all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (uuidField[i] != 0x00) all_zero = FALSE;
                    if (uuidField[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    // SMBIOS 2.6+ UUID 前3个字段是小端
                    uuid[0] = uuidField[3];
                    uuid[1] = uuidField[2];
                    uuid[2] = uuidField[1];
                    uuid[3] = uuidField[0];
                    uuid[4] = uuidField[5];
                    uuid[5] = uuidField[4];
                    uuid[6] = uuidField[7];
                    uuid[7] = uuidField[6];
                    for (int i = 8; i < 16; i++)
                        uuid[i] = uuidField[i];

                    result = TRUE;
                }
                break;
            }

             // 跳过 formatted area
            UCHAR* next = data + h->length;
            // 跳过 unformatted strings 区域 (以 0x0000 结束)
            while (next < smb->SMBIOSTableData + smb->Length &&
                (next[0] != 0 || next[1] != 0))
                next++;
            next += 2;
            data = next;
        }

        free(buffer);
        return result;
    }

    // 转换 wchar_t* 到 std::string (UTF-8 编码)
    std::string WcharToString(const wchar_t* wstr)
    {
        if (!wstr) return std::string();

        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return std::string();

        std::string str(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
        return str;
    }

     // 初始化并格式化为 UUID 字符串
    std::string InitFwUuid()
    {
        wchar_t g_uuid_str[40] = { 0 };
        UCHAR uuid[16];
        if (GetFwUuid(uuid))
        {
            wchar_t* ptr = g_uuid_str;
            int i;
            for (i = 0; i < 4; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 6; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 8; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 10; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 16; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = 0;
        }
        else {
            wcscpy_s(g_uuid_str, L"00000000-0000-0000-0000-000000000000");
        }
        return WcharToString(g_uuid_str);
    }

    /**
     * @brief 从SbieDrv.sys 扫描 KphpTrustedPublicKey 获取 RVA
     *
     * @param sbieDrvPath SbieDrv.sys 的用户态文件路径
     * @return RVA 偏移, 失败返回 0
     */
    uint64_t GetKphVerifySignatureOffset(const std::string& sbieDrvPath)
    {
        std::vector<uint8_t> fileData;
        if (!Utils::ReadFileToMem(sbieDrvPath, fileData)) {
            std::cerr << "[!] Failed to read: " << sbieDrvPath << std::endl;
            return 0;
        }
        if (fileData.size() < sizeof(IMAGE_DOS_HEADER))
            return 0;

        uint8_t* base = fileData.data();
        size_t fileSize = fileData.size();
        // DOS Header
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if ((size_t)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize)
            return 0;
        // NT Headers
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        // Section Headers
        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
        WORD numSections = ntHeaders->FileHeader.NumberOfSections;
        constexpr size_t patternSize = sizeof(KphpOriginalPublicKey);
        for (WORD i = 0; i < numSections; i++) {
            if ( (memcmp(sections[i].Name, ".data", 5) != 0) && 
                (memcmp(sections[i].Name, ".rdata", 6) != 0) ) {
                
                continue;
            }

            DWORD rawOffset = sections[i].PointerToRawData;
            DWORD rawSize = sections[i].SizeOfRawData;
            DWORD sectionRva = sections[i].VirtualAddress;
            if (rawOffset + rawSize > fileSize)
                continue;
            if (rawSize < patternSize)
                continue;
            // 在该段的原始数据中扫描特征码
            uint8_t* sectionBase = base + rawOffset;
            for (DWORD j = 0; j + patternSize <= rawSize; j++) {
                if (memcmp(sectionBase + j, KphpOriginalPublicKey, patternSize) == 0) {
                    return static_cast<uint64_t>(sectionRva + j);
                }
            }

        }
        return 0;
	}
}