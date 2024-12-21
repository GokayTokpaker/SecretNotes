import tkinter
from tkinter import messagebox, END
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get(index1=1.0,index2=END)
    masterkey=input_key.get()

    if len(title) == 0 or len(message) == 0 or len(masterkey) == 0:
        messagebox.showinfo("Error",message="Please enter all info")
    else:
        message_en=encode(masterkey,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_en}")
        except(FileNotFoundError):
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_en}")
        finally:
            title_entry.delete(0,END)
            input_key.delete(0,END)
            input_text.delete("1.0",END)

def decrypt_notes():
    message_enc = input_text.get("1.0",END)
    master_key = input_key.get()

    if len(message_enc) == 0 and len(master_key)== 0:
        messagebox.showinfo("Error","Please enter key and message")
    else:
        try:
            message_de=decode(master_key,message_enc)
            input_text.delete("1.0",END)
            input_text.insert("1.0",message_de)
        except:
            messagebox.showinfo(title="Error",message="Please enter key!")


# User Interface
FONT=("Verdena",10,"normal")
window = tkinter.Tk()
window.config(padx=30,pady=30)
window.title("Secret Notes")


title_info_label = tkinter.Label(text="Enter your title",font=FONT)
title_info_label.pack()
title_entry = tkinter.Entry(width=30)
title_entry.pack()

secret_info_label = tkinter.Label(text="Enter your secret",font=FONT)
secret_info_label.pack()

input_text = tkinter.Text(width=30,height=20)
input_text.pack()

key_info_label = tkinter.Label(text="Enter master key",font=FONT)
key_info_label.pack()

input_key = tkinter.Entry(width=30)
input_key.pack()

save_button = tkinter.Button(text="Save/Encrypt",command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = tkinter.Button(text="Decrypt",command=decrypt_notes)
decrypt_button.pack()


window.mainloop()
