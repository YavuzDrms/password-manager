#include <iostream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <vector>

class Password{
public:
    Password(std::string name,std::string password){
        this->m_Name = name;
        this->m_Password = password;
    }
    ~Password(){}

    std::string getName() {return m_Name;}
    std::string getPassword() {return m_Password;}

    void setName(std::string a){this->m_Name = a;}
    void setPassword(std::string a){this->m_Password = a;}

private:
    std::string m_Name;
    std::string m_Password;
};
std::vector<Password> passwords;

std::string mainPassowrd = "QWRmz_A@1_!";
std::string encryptionKey = "encYripTiOnKe1Y@#!_";
std::string folderPath;
std::string filePath;
// this is the master password
// you can change this whatever you want
// you have to enter this password to learn another passwords

std::string commands[6] = {"help", "exit", "add", "list", "get", "clear"};

std::string xorEncryptDecrypt(const std::string& data, const std::string& key) {
    std::string result = data;
    int keyLen = key.length();
    
    for (size_t i = 0; i < data.length(); i++) {
        result[i] = data[i] ^ key[i % keyLen];
    }
    
    return result;
}
std::string toHex(const std::string& data) {
    std::string hex;
    const char hexChars[] = "0123456789ABCDEF";
    
    for (unsigned char c : data) {
        hex += hexChars[c >> 4];
        hex += hexChars[c & 0x0F];
    }
    
    return hex;
}
std::string fromHex(const std::string& hex) {
    std::string result;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
        result += chr;
    }
    
    return result;
}

void savePasswords(){
    std::ofstream file(filePath);
    if(!file.is_open()){
        std::cout << "Cant open passwords file.\n";
        std::exit(-1);
    }
    
    for (auto& pass : passwords){
        std::string name = pass.getName();
        std::string password = pass.getPassword();
        
        std::string encryptedName = xorEncryptDecrypt(name, encryptionKey);
        std::string encryptedPassword = xorEncryptDecrypt(password, encryptionKey);
        
        std::string hexName = toHex(encryptedName);
        std::string hexPassword = toHex(encryptedPassword);
        
        file << hexName << std::endl;
        file << hexPassword << std::endl;
    }

    file.close();
    std::cout << "Passwords saved \n";
}
void loadPasswords(){
    std::ifstream file(filePath);
    
    if(!file.is_open()){
        std::cout << "No existing passwords file." << std::endl;
        return;
    }
    
    std::string hexName, hexPassword;
    
    while(std::getline(file, hexName)){
        if(std::getline(file, hexPassword)){
            std::string encryptedName = fromHex(hexName);
            std::string encryptedPassword = fromHex(hexPassword);
            
            std::string name = xorEncryptDecrypt(encryptedName, encryptionKey);
            std::string password = xorEncryptDecrypt(encryptedPassword, encryptionKey);
            
            Password p(name, password);
            passwords.push_back(p);
        }
    }
    
    file.close();
}
void addPasword(){
    std::string n, p;
    std::cout << "-> Add new password \n";
    std::cout << "--> Name\n";
    std::cin.ignore();

    std::getline(std::cin, n);

    std::cout << "--> Passwords\n";
    std::getline(std::cin, p);

    Password newPass(n,p);
    passwords.push_back(newPass);

    std::cout << "Password added.\n";
    savePasswords();
}
void listPasswords(){
    if(passwords.empty()){
        std::cout << "\nNo passwords stored." << std::endl;
        return;
    }
    
    std::cout << "\n-> All Passwords" << std::endl;
    std::cout << "-------------------------" << std::endl;
    
    int index = 1;
    for(auto& pass : passwords){
        std::cout << "[" << index << "] " << pass.getName() << std::endl;
        std::cout << "    Password: " << pass.getPassword() << std::endl;
        std::cout << "-------------------------" << std::endl;
        index++;
    }
    
    std::cout << "Total: " << passwords.size() << " passwords" << std::endl;
}
void getPassword(){
    if(passwords.empty()){
        std::cout << "\nNo passwords stored." << std::endl;
        return;
    }
    
    std::string searchName;
    std::cout << "Enter service/website name: ";
    std::cin.ignore();
    std::getline(std::cin, searchName);
    
    bool found = false;
    
    for(auto& pass : passwords){
        if(pass.getName() == searchName){
            std::cout << "\nFound!" << std::endl;
            std::cout << "Service: " << pass.getName() << std::endl;
            std::cout << "Password: " << pass.getPassword() << std::endl;
            found = true;
            break;
        }
    }
    
    if(!found){
        std::cout << "Password not found!" << std::endl;
    }
}
void clearPasswords(){
    std::cout << "Deleting all passwords. \n";
    std::ofstream file(filePath);
    std::cout << "Deleted. \n";
}

void help(){
    for(auto& a : commands){
        std::cout << a << " -> ";
        if (a == "help"){
            std::cout << "Get help for program.\n";
        }else if(a == "exit"){
            std::cout << "Exit program.\n";
        }else if(a == "add"){
            std::cout << "Add password.\n";
        }else if(a == "list"){
            std::cout << "List all passwords.\n";
        }else if(a == "get"){
            std::cout << "Get spesific password.\n";
        }else if (a == "help"){
            std::cout << "Clear all paswords.\n";
        }
    }
}

int get_command()
{
    std::string command;
    while(1)
    {
        std::cout << "Enter command (for help type help): " <<std::endl;
        std::cin >> command;
        for(auto &a : commands)
        {
            if (a == command){
                if (command == "help"){
                    help();
                    break;
                }
                else if(command == "exit"){
                    savePasswords();
                    std::exit(0);
                    break;
                }else if(command == "add"){
                    addPasword();
                    break;
                }else if (command == "list"){
                    listPasswords();
                    break;
                }else if (command == "get"){
                    getPassword();
                    break;
                }else if(command == "clear"){
                    clearPasswords();
                    break;
                }
            }
        }
    }
    return 0;
}

int main()
{
    // get %appdata% enverioment
    // check if there is and passwordmanager folder
    // if there is, there is no problem
    // if isn't, create it
    char* appdata = getenv("APPDATA");
    if(appdata == NULL){
        std::cout << "Couldn't find appdata \n";
        return 1;
    }
    folderPath = std::string(appdata) + "\\passwordmanager";
    filePath = folderPath + "\\passwords.txt";
    if (std::filesystem::exists(folderPath)){
        std::cout << "Passwordmanager found" << std::endl;
    }else{    
        if(std::filesystem::create_directories(folderPath)){
            std::cout << "Folder created" << std::endl;
        }else{
            std::cout << "Can't create folder" << std::endl;
            return 1;
        }
    }
    if(std::filesystem::exists(filePath)){
        std::cout << "Password file found\n";
    }else{
        std::ofstream {filePath};
        std::cout << "Created password file\n";
    }

    std::string inputPassword;
    int attemp = 1;
    while(1)
    {
        std::cout << "[" << attemp << "]" << "Enter password:" << std::endl;
        std::cin >> inputPassword;
        if (inputPassword == mainPassowrd)
        {
            std::cout << "Correct" << std::endl;
            encryptionKey = mainPassowrd;
            int cmd = get_command();
        }
        else{
            std::cout << "Wrong" <<std::endl;
            attemp++;
        }

        if (attemp >= 4){
            break;
        }
    }

    return 0;
}