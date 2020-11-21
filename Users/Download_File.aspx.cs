using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Configuration;
using System.Net;

public partial class Users_Download_File : System.Web.UI.Page
{
    public string file_path, key, fileName, fileExtension, output, input_file;
    public static string cs = ConfigurationManager.ConnectionStrings["dbConnection"].ConnectionString;
    public SqlConnection conn;
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Session["user_id"] == "")
        {
            Response.Redirect("Login.aspx?msg=logout");
        }
    }

    protected void btnSave_Click(object sender, EventArgs e)
    {
         conn=new SqlConnection(cs);
        string share_id = Request.QueryString["share_id"];
        string query = "select file_name,fid from Share_Master where share_id='" + share_id + "'";
        DataTable dt = Database.Getdata(query);

        string file_name = Convert.ToString(dt.Rows[0]["file_name"]);
        int fileid = Convert.ToInt32(dt.Rows[0]["fid"]);

        using (SqlCommand cmd = new SqlCommand("select * from file_master where key_value=@key_value", conn))
        {
            cmd.Parameters.AddWithValue("@key_value", txtsecret_key.Text);
            using (SqlDataAdapter adp = new SqlDataAdapter(cmd))
            {
                DataTable dt1 = new DataTable();
                adp.Fill(dt1);
                if (dt1.Rows.Count > 0)
                {
                    file_path = Convert.ToString(dt1.Rows[0]["file_path"]);
                    fileName = Path.GetFileNameWithoutExtension(file_path);
                    fileExtension = Path.GetExtension(file_path);
                    output = Server.MapPath("../Files/"+fileName + "_dec" + fileExtension);
                    input_file = Server.MapPath("../Files/" + file_path);
                    key = txtsecret_key.Text;
                    Decrypt(key, input_file, output);
                    WebClient req = new WebClient();
                    HttpResponse response = HttpContext.Current.Response;
                    string filePath = "~/Files/" + fileName + "_dec" + fileExtension;
                    response.Clear();
                    response.ClearContent();
                    response.ClearHeaders();
                    response.Buffer = true;
                    response.AddHeader("Content-Disposition", "attachment;filename=" + dt1.Rows[0]["file_name"].ToString());
                    byte[] data = req.DownloadData(Server.MapPath(filePath));
                    response.BinaryWrite(data);
                    response.End();
                }
            }
        }



    }

    private void Decrypt(string key, string inputFilePath, string outputfilePath)
            {
                string EncryptionKey = key;
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                    {
                        using (CryptoStream cs = new CryptoStream(fsInput, encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            using (FileStream fsOutput = new FileStream(outputfilePath, FileMode.Create))
                            {
                                int data;
                                while ((data = cs.ReadByte()) != -1)
                                {
                                    fsOutput.WriteByte((byte)data);

                                    
                                }
                            }
                        }
                    }
                }
            }
}