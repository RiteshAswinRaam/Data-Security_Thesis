<%@ Page Language="C#" AutoEventWireup="true" CodeFile="Upload_File.aspx.cs" Inherits="Upload_File" %>

<%@ Register TagPrefix="uc1" TagName="header" Src="~/Admin/Includes/Header.ascx" %>
<%@ Register TagPrefix="uc2" TagName="footer" Src="~/Admin/Includes/Footer.ascx" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Home</title>
    <meta name="description" content="" />
    <meta name="keywords" content="" />
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    <link href="css/style.css" rel="stylesheet" type="text/css" />
</head>
<body>
    <form id="form1" runat="server">
    <div class="page-out">
        <div class="page-in">
            <div class="page">
                <div class="main">
                    <uc1:header ID="header" runat="server" />
                    <div class="content">
                        <table class="style1" cellpadding="5" cellspacing="5">
                            <tr>
                                <td class="style2">
                                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Select
                                    File:-
                                </td>
                                <td class="style3">
                                    <asp:FileUpload ID="FileUpload1" runat="server" accept="image/x-png,image/gif,image/jpeg" />
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>
                            <%-- <tr>
                                <td class="style2">
                                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Select
                                    Key1:-
                                </td>
                                <td class="style3">
                                    <asp:DropDownList ID="ddlKey1" runat="server" Width="200px" DataSourceID="SqlDataSource1"
                                        DataTextField="key_value" DataValueField="key_id" AppendDataBoundItems="true">
                                        <asp:ListItem Selected="True" Value="0" Text="Select First Key"></asp:ListItem>
                                    </asp:DropDownList>
                                    <asp:SqlDataSource ID="SqlDataSource1" runat="server" ConnectionString="<%$ ConnectionStrings:dbConnection %>"
                                        SelectCommand="SELECT * FROM [auto_keys]"></asp:SqlDataSource>
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>--%>
                            <%--        <tr>
                                <td class="style2">
                                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Select
                                    Key2:-
                                </td>
                                <td class="style3">
                                    <asp:DropDownList ID="ddlKey2" runat="server" Width="200px" DataSourceID="SqlDataSource1"
                                        DataTextField="key_value" DataValueField="key_id" AppendDataBoundItems="true">
                                        <asp:ListItem Selected="True" Value="0" Text="Select Second Key"></asp:ListItem>
                                    </asp:DropDownList>
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>
                            <tr>
                                <td class="style2">
                                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Select
                                    Key3:-
                                </td>
                                <td class="style3">
                                    <asp:DropDownList ID="ddlKey3" runat="server" Width="200px" DataSourceID="SqlDataSource1"
                                        DataTextField="key_value" DataValueField="key_id" AppendDataBoundItems="true">
                                        <asp:ListItem Selected="True" Value="0" Text="Select Third Key"></asp:ListItem>
                                    </asp:DropDownList>
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>--%>
                            <tr>
                                <td class="style2">
                                    &nbsp;
                                </td>
                                <td class="style3">
                                    <asp:Button ID="btnSave" runat="server" Height="25px" Text="Encrypt" Width="70px"
                                        OnClick="btnSave_Click" />
                                    &nbsp;&nbsp;&nbsp;
                                    <asp:Button ID="btnCancel" runat="server" Height="25px" Text="Cancel" Width="70px" />
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>
                            <tr>
                                <td class="style2">
                                    &nbsp;
                                </td>
                                <td class="style3">
                                    &nbsp;
                                </td>
                                <td>
                                    &nbsp;
                                </td>
                            </tr>
                        </table>
                    </div>
                    <uc2:footer ID="footer" runat="server" />
                </div>
            </div>
        </div>
    </div>
    </form>
</body>
</html>
