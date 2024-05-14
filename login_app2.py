import functools
import tkinter as tk

from user_login_protocol import UserLoginProtocol
# TODO:

# Create a hard coded dictionary of user -> UserData (class)
# when doing login/signup then check if user in dictionary and if password matches
# add new key and UserData to dictionary if user doesn't exist


class LoginApp(tk.Tk):

    user_login_protocol: UserLoginProtocol = None

    def __init__(self, user_login_protocol):
        super().__init__()
        self.user_login_protocol = user_login_protocol
        self.current_frame = None

    def run(self):
        self.show_frame(LoginFrame)
        self.mainloop()

    def show_frame(self, frame_class):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = frame_class(self)
        self.current_frame.pack()


class LoginFrame(tk.Frame):
    login_result_label = None

    def login_clicked(self, user, password):
        print(f"email:{user.get()}, pass:{password.get()}")
        login_response = self.master.user_login_protocol.login(user.get(), password.get())

        if login_response.result:
            message = "Login Succeeded!"
            fg = "green"
        else:
            message = f"Login Failed: {login_response.error}"
            fg = "red"

        if self.login_result_label is not None:
            self.login_result_label.config(text=message, fg=fg)
        else:
            self.login_result_label = tk.Label(self, text=message, fg=fg)
            self.login_result_label.pack()



    def __init__(self, master:LoginApp):
        super().__init__(master)
        master.title("Login")
        master.geometry("400x250")

        user = tk.StringVar()
        password = tk.StringVar()

        user_label = tk.Label(self, text="User Name:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.login_clicked, user, password)

        login_button = tk.Button(self, text="Login", command=partial_func)
        login_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))

        label2 = tk.Label(self, text="Forgot Password", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(ForgotPassword))

class SignUpFrame(tk.Frame):
    sign_up_result_label = None

    def sign_up_clicked(self, user, email, password, reenter_password):
        if password.get() != reenter_password.get():
            message = f"Passwords don't match"
            fg = "red"
        else:
            sign_up_response = self.master.user_login_protocol.sign_up(user.get(), email.get(), password.get())
            if sign_up_response.result:
                message = "Sign Up Succeeded!"
                fg = "green"
            else:
                message = f"Sign Up Failed: {sign_up_response.error}"
                fg = "red"

        if self.sign_up_result_label is not None:
            self.sign_up_result_label.config(text=message, fg=fg)
        else:
            self.sign_up_result_label = tk.Label(self, text=message, fg=fg)
            self.sign_up_result_label.pack()

    def __init__(self, master:LoginApp):
        super().__init__(master)

        master.title("Sign Up")
        master.geometry("400x250")

        user = tk.StringVar()
        email = tk.StringVar()
        password = tk.StringVar()
        reenter_password = tk.StringVar()

        user_label = tk.Label(self, text="User Name:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        email_label = tk.Label(self, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)

        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        reenter_password_label = tk.Label(self, text="Reenter Password:")
        reenter_password_label.pack(fill='x', expand=True)

        reenter_password_entry = tk.Entry(self, textvariable=reenter_password, show="*")
        reenter_password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.sign_up_clicked, user, email, password, reenter_password)

        # login button
        sign_up_button = tk.Button(self, text="Login", command=partial_func)
        sign_up_button.pack(fill='x', expand=True, pady=10)


        label = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

        label2 = tk.Label(self, text="Forgot Password", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(ForgotPassword))


class ForgotPassword(tk.Frame):

    def forgot_password_clicked(self, user):
        print(f"email:{user.get()}")
        forgot_password_response = self.master.user_login_protocol.forgot_password(user.get())

        if forgot_password_response.result:
            message = "Send code Succeeded!"
            fg = "green"
        else:
            message = f"Login Failed: {forgot_password_response.error}"
            fg = "red"

        if self.forgot_password_result_label is not None:
            self.forgot_password_result_label.config(text=message, fg=fg)
        else:
            self.forgot_password_result_label = tk.Label(self, text=message, fg=fg)
            self.forgot_password_result_label.pack()

    def __init__(self, master:LoginApp):
        super().__init__(master)

        master.title("Forgot Password")
        master.geometry("400x250")

        user = tk.StringVar()

        user_label = tk.Label(self, text="User Name For Recovery:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        partial_func = functools.partial(self.forgot_password_clicked, user)

        send_code_to_email_button = tk.Button(self, text="Send Code To Email", command=partial_func)
        send_code_to_email_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))

        label2 = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))


