import pandas

input_source='/Users/calange/github/lab/cml/'
labname="vxlan_xr"
input_excel_file=input_source+labname+'/cml.xlsx'

# input_source='/Users/calange/github/lab/autopods/'
# labname="vxlan_xr"
# input_excel_file=input_source+labname+'/autopods.xlsx'

def Main():

    # new_session = crt.OpenSessionConfiguration("Teste")
    # user = new_session.GetOption("password")
    # crt.Dialog.MessageBox(user)
    excel = pandas.read_excel(input_excel_file, sheet_name='Routers')
    for line in excel.index:
        new_session = crt.OpenSessionConfiguration()
        new_session.SetOption("Hostname", excel['MGMT_IP'][line].split('/')[0])
        new_session.SetOption("Username", excel['USERNAME'][line])
        new_session.SetOption("Password", excel['SECURECRT_ENCRYPTED_PASSWORD'][line])
        new_session.SetOption("Protocol Name", "SSH2")
        new_session.SetOption("Session Password Saved", 1)
        if excel['JUMPBOX'].isnull()[line] == False:
            new_session.SetOption("Firewall Name", "Session:%s" % excel['JUMPBOX'][line])
        new_session.Save("%s/%s" %(labname, excel['HOSTNAME'][line]))

Main()
