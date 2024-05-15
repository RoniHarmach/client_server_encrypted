import functools
import tkinter as tk

from encryption import Encryption, EncryptionData
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

    def show_frame(self, frame_class, args=None):
        if self.current_frame:
            self.current_frame.destroy()
        if args is None:
            self.current_frame = frame_class(self)
        else:
            self.current_frame = frame_class(self, args)
        self.current_frame.pack()


class LoginFrame(tk.Frame):
    login_result_label = None

    def login_clicked(self, email, password):
        print(f"email:{email.get()}, pass:{password.get()}")
        login_response = self.master.user_login_protocol.login(email.get(), password.get())

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
        master.geometry("500x400")

        email = tk.StringVar()
        password = tk.StringVar()

        email_label = tk.Label(self, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)
        email_entry.focus()

        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.login_clicked, email, password)

        login_button = tk.Button(self, text="Login", command=partial_func)
        login_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))

        label2 = tk.Label(self, text="Forgot Password", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(ForgotPassword))

        label3 = tk.Label(self, text="Reset Password", fg="blue", cursor="hand2")
        label3.pack()
        label3.bind("<Button-1>", lambda event: master.show_frame(ResetPassword))

        label4 = tk.Label(self, text="Verify Sign Up", fg="blue", cursor="hand2")
        label4.pack()
        label4.bind("<Button-1>", lambda event: master.show_frame(SignUpVerificationFrame, ""))


class SignUpFrame(tk.Frame):
    sign_up_result_label = None

    def sign_up_clicked(self, email, password, reenter_password, master: LoginApp):
        if password.get() != reenter_password.get():
            message = f"Passwords don't match"
            fg = "red"
        else:
            sign_up_response = self.master.user_login_protocol.sign_up(email.get(), password.get())
            if sign_up_response.result:
                master.show_frame(SignUpVerificationFrame, email.get())
                return
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
        master.geometry("500x400")

        email = tk.StringVar()
        password = tk.StringVar()
        reenter_password = tk.StringVar()

        email_label = tk.Label(self, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)
        email_entry.focus()

        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        reenter_password_label = tk.Label(self, text="Reenter Password:")
        reenter_password_label.pack(fill='x', expand=True)

        reenter_password_entry = tk.Entry(self, textvariable=reenter_password, show="*")
        reenter_password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.sign_up_clicked, email, password, reenter_password, master)

        sign_up_button = tk.Button(self, text="Sign Up", command=partial_func)
        sign_up_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

        label2 = tk.Label(self, text="Forgot Password", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(ForgotPassword))


class ResetPassword(tk.Frame):
    reset_result_label = None

    def reset_password_clicked(self, email, password, reenter_password, reset_code):
        if password.get() != reenter_password.get():
            message = f"Passwords don't match"
            fg = "red"
        else:
            response = self.master.user_login_protocol.reset_password(email.get(), password.get(), reset_code.get())
            if response.result:
                message = "Your password was reset"
                fg = "green"
            else:
                message = f"Reset password failed: {response.error}"

        if self.reset_result_label is not None:
            self.reset_result_label.config(text=message, fg=fg)
        else:
            self.reset_result_label = tk.Label(self, text=message, fg=fg)
            self.reset_result_label.pack()

    def __init__(self, master:LoginApp):
        super().__init__(master)

        master.title("Reset Password")
        master.geometry("500x400")

        email = tk.StringVar()
        reset_code = tk.IntVar()
        password = tk.StringVar()
        reenter_password = tk.StringVar()

        email_label = tk.Label(self, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)
        email_entry.focus()

        reset_code_label = tk.Label(self, text="Reset password code(sent to your email):")
        reset_code_label.pack(fill='x', expand=True)

        reset_code_entry = tk.Entry(self, textvariable=reset_code)
        reset_code_entry.pack(fill='x', expand=True)
        reset_code_entry.focus()

        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        reenter_password_label = tk.Label(self, text="Reenter Password:")
        reenter_password_label.pack(fill='x', expand=True)

        reenter_password_entry = tk.Entry(self, textvariable=reenter_password, show="*")
        reenter_password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.reset_password_clicked, email, password, reenter_password, reset_code)

        sign_up_button = tk.Button(self, text="Reset", command=partial_func)
        sign_up_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

        label2 = tk.Label(self, text="Forgot Password", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(ForgotPassword))


class ForgotPassword(tk.Frame):
    forgot_password_result_label = None

    def forgot_password_clicked(self, email):
        print(f"email:{email.get()}")
        forgot_password_response = self.master.user_login_protocol.forgot_password(email.get())

        if forgot_password_response.result:
            message = "If you have an account, check your email for reset code and go to 'Reset Password' window"
            fg = "green"
        else:
            message = f"Failed to request password recover: {forgot_password_response.error}"
            fg = "red"

        if self.forgot_password_result_label is not None:
            self.forgot_password_result_label.config(text=message, fg=fg)
        else:
            self.forgot_password_result_label = tk.Label(self, text=message, fg=fg)
            self.forgot_password_result_label.pack()

    def __init__(self, master:LoginApp):
        super().__init__(master)

        master.title("Forgot Password")
        master.geometry("500x400")

        email = tk.StringVar()

        email_label = tk.Label(self, text="Email For Recovery:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)
        email_entry.focus()

        partial_func = functools.partial(self.forgot_password_clicked, email)

        send_code_to_email_button = tk.Button(self, text="Send Code To Email", command=partial_func)
        send_code_to_email_button.pack(fill='x', expand=True, pady=10)

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))

        label2 = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label2.pack()
        label2.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

        label3 = tk.Label(self, text="Reset Password", fg="blue", cursor="hand2")
        label3.pack()
        label3.bind("<Button-1>", lambda event: master.show_frame(ResetPassword))


class SignUpVerificationFrame(tk.Frame):
    verification_result_label = None
    login_link : tk.Label = None
    verify_button: tk.Button = None
    verification_code_entry: tk.Entry = None

    def resend_clicked(self, email=""):
        response = self.master.user_login_protocol.resend_sign_up_code(email.get())
        if not response.result:
            message = response.error
            fg = "red"
        else:
            message = "Check your email for verification code"
            fg = "green"

        if self.verification_result_label is not None:
            self.verification_result_label.config(text=message, fg=fg)
        else:
            self.verification_result_label = tk.Label(self, text=message, fg=fg)
            self.verification_result_label.pack()

    def verify_clicked(self, email, verification_code):
        response = self.master.user_login_protocol.verify_sign_up(email.get(), verification_code.get())
        if not response.result:
            message = response.error
            fg = "red"
        else:
            message = f"Sign up process finished"
            fg = "green"
            self.login_label.pack()
            self.verify_button.config(state=tk.DISABLED)
            self.verification_code_entry.config(state=tk.DISABLED)
            self.resend_button.config(state=tk.DISABLED)

        if self.verification_result_label is not None:
            self.verification_result_label.config(text=message, fg=fg)
        else:
            self.verification_result_label = tk.Label(self, text=message, fg=fg)
            self.verification_result_label.pack()



    def __init__(self, master:LoginApp, email):
        super().__init__(master)

        master.title("Verify Sign Up")
        master.geometry("500x400")

        email_str = tk.StringVar()
        email_str.set(email)
        verification_code = tk.IntVar()

        email_label = tk.Label(self, text="Please verify code sent to your email:")
        email_label.pack(fill='x', expand=True)

        self.email_entry = tk.Entry(self, textvariable=email_str)
        self.email_entry.pack(fill='x', expand=True)
        self.email_entry.focus()

        verification_code_label = tk.Label(self, text="Please verify code sent to your email:")
        verification_code_label.pack(fill='x', expand=True)

        self.verification_code_entry = tk.Entry(self, textvariable=verification_code)
        self.verification_code_entry.pack(fill='x', expand=True)
        self.verification_code_entry.focus()

        verify_func = functools.partial(self.verify_clicked, email_str, verification_code)
        self.verify_button = tk.Button(self, text="Verify Code", command=verify_func)
        self.verify_button.pack(fill='x', expand=True, pady=10)

        resend_func = functools.partial(self.resend_clicked, email_str)
        self.resend_button = tk.Button(self, text="Resend Code", command=resend_func)
        self.resend_button.pack(fill='x', expand=True, pady=10)

        self.login_label = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        self.login_label.pack()
        self.login_label.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))



# אם לוחצצים על הרשמות אחרי שפעם אחת לא הצלחת זה תוקע את המסך

