import tkinter
import tkinter.messagebox
from tkinter import ttk, filedialog
from tkinter.filedialog import askopenfile
import customtkinter
from OpenSSL import crypto, SSL


def cert_gen(emailAddress, commonName, countryName, localityName, stateOrProvinceName, organizationName, organizationUnitName, serialNumber=0, validityStartInSeconds=0,
    validityEndInSeconds=365*24*60*60, KEY_FILE = "private.key", CERT_FILE="certificate.crt"):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    print('The Self-Signed Certificate is generated in the file "certificate.crt"\n')
    print('Certificate Infos : \n')
    print('Email Address : ',emailAddress,' ,Common Name : ',commonName,' ,Country Name : ',countryName,' ,Locality Name : ',localityName,
    ' ,State of Province Name : ',stateOrProvinceName,' ,Organization Name : ',organizationName,' ,Organization Unit Name : ',organizationUnitName,
    ' ,Validity : 365 days.')
customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

f = customtkinter.CTk()
f.title("Certificate Generator")
f.geometry(f"{900}x{900}")



# create main entry and button
f.logo_label = customtkinter.CTkLabel(f, text="Certificate Generator", font=customtkinter.CTkFont(size=20, weight="bold"))
f.logo_label.grid(row=0, column=6, padx=20, pady=(20, 10))
f.label_countryName = customtkinter.CTkLabel(f, text="Country Name : (must be 2 letters only)",  font=("Times", 18, "bold"))
f.label_countryName.grid(row=1, column=4, padx=20, pady=20)
f.countryName = customtkinter.CTkEntry(f)
f.countryName.grid(row=1, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_stateOrProvinceName = customtkinter.CTkLabel(f, text="State or Province Name :",  font=("Times", 18, "bold"))
f.label_stateOrProvinceName.grid(row=2, column=4, padx=20, pady=20)
f.stateOrProvinceName = customtkinter.CTkEntry(f)
f.stateOrProvinceName.grid(row=2, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_localityName = customtkinter.CTkLabel(f, text="Locality Name : ",  font=("Times", 18, "bold"))
f.label_localityName.grid(row=3, column=4, padx=20, pady=20)
f.localityName = customtkinter.CTkEntry(f)
f.localityName.grid(row=3, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_organizationName = customtkinter.CTkLabel(f, text="Organization Name : ",  font=("Times", 18, "bold"))
f.label_organizationName.grid(row=4, column=4, padx=20, pady=20)
f.organizationName = customtkinter.CTkEntry(f)
f.organizationName.grid(row=4, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_organizationUnitName = customtkinter.CTkLabel(f, text="Organization Unit Name : ",  font=("Times", 18, "bold"))
f.label_organizationUnitName.grid(row=5, column=4, padx=20, pady=20)
f.organizationUnitName = customtkinter.CTkEntry(f)
f.organizationUnitName.grid(row=5, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_emailAddress = customtkinter.CTkLabel(f, text="Email Address : ",  font=("Times", 18, "bold"))
f.label_emailAddress.grid(row=6, column=4, padx=20, pady=20)
f.emailAddress = customtkinter.CTkEntry(f)
f.emailAddress.grid(row=6, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.label_commonName = customtkinter.CTkLabel(f, text="Common Name : ",  font=("Times", 18, "bold"))
f.label_commonName.grid(row=7, column=4, padx=20, pady=20)
f.commonName = customtkinter.CTkEntry(f)
f.commonName.grid(row=7, column=6, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")
f.key_label = customtkinter.CTkLabel(f, text="", font=("Times", 18, "bold"))
f.key_label.grid(row=8, column=4, padx=20, pady=(20, 10))
f.cert_label = customtkinter.CTkLabel(f, text="", font=("Times", 18, "bold"))
f.cert_label.grid(row=9, column=4, padx=20, pady=(20, 10))
f.button_cert_file = customtkinter.CTkButton(master=f, border_width=2, text="Generate Certificate", command=lambda: [cert_gen(f.emailAddress.get(), f.commonName.get(), f.countryName.get(), f.localityName.get(), f.stateOrProvinceName.get(), f.organizationName.get(), f.organizationUnitName.get()),f.key_label.configure(text="Key generated at 'private.key'"), f.cert_label.configure(text="Certificate generated at 'certificate.crt'")])
f.button_cert_file.grid(row=8, column=8, padx=(20, 20), pady=(20, 20), sticky="nsew")

if __name__ == "__main__":
    
    f.mainloop()    