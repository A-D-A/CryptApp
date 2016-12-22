using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using CryproLib;
using System.IO;

namespace CryptApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnEncryptSymm_Click(object sender, RoutedEventArgs e)
        {
            CryptoProvider cp = new CryptoProvider();
            cp.SetCryptoAlgorithm(new GOST28147_89());
            MemoryStream inputData = new MemoryStream(Encoding.Default.GetBytes(tbInputSymm.Text));
            MemoryStream outputData = new MemoryStream();
            cp.Encrypt(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);
      
            var hexString = BitConverter.ToString(buf);
            hexString = hexString.Replace("-", " ");
            tbOutSymm.Text = hexString;
        }

        private void btnDecryptSymm_Click(object sender, RoutedEventArgs e)
        {
            CryptoProvider cp = new CryptoProvider();
            cp.SetCryptoAlgorithm(new GOST28147_89());

            MemoryStream inputData = new MemoryStream(FromHex(tbOutSymm.Text));
            MemoryStream outputData = new MemoryStream();
            cp.Decrypt(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);
            tbOutSymm.Text = Encoding.Default.GetString(buf);

        }
        public static byte[] FromHex(string hex)
        {
            byte[] raw = null;
            try
            {
                hex = hex.Replace(" ", "");
                raw = new byte[hex.Length / 2];
                for (int i = 0; i < raw.Length; i++)
                {
                    raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                }
                return raw; 
            }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Некорректные входные данные"); }
            return null;
        }
        private void btnEncryptAsymm_Click(object sender, RoutedEventArgs e)
        {
            CryptoProvider cp = new CryptoProvider();
            cp.SetCryptoAlgorithm(new ElGamal());

            MemoryStream inputData = new MemoryStream(Encoding.Default.GetBytes(tbInputAsymm.Text));
            MemoryStream outputData = new MemoryStream();
            cp.Encrypt(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);
          
            //tbOutAsymm.Text = Encoding.Default.GetString(buf);

            var hexString = BitConverter.ToString(buf);
            hexString = hexString.Replace("-", " ");
            tbOutAsymm.Text = hexString;
        }

        private void btnDecryptAsymm_Click(object sender, RoutedEventArgs e)
        {
            CryptoProvider cp = new CryptoProvider();
            cp.SetCryptoAlgorithm(new ElGamal());

            MemoryStream inputData = new MemoryStream(FromHex(tbOutAsymm.Text));
            MemoryStream outputData = new MemoryStream();
            cp.Decrypt(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);

            tbOutAsymm.Text = Encoding.Default.GetString(buf);
        }

        private void btnCheckHash_Click(object sender, RoutedEventArgs e)
        {
            MD5 hash = new MD5();
            MemoryStream inputData = new MemoryStream(Encoding.Default.GetBytes(tbInputHash.Text));
            MemoryStream outputData = new MemoryStream();
            hash.GetHash(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);
            if (tbOutHash.Text == Encoding.Default.GetString(buf))
                tbOutHash.Text += "\n Хеш совпадает";
            else tbOutHash.Text += "\n Хеш не совпадает";
        }

        private void btnGetHash_Click(object sender, RoutedEventArgs e)
        {
            MD5 hash = new MD5();
            MemoryStream inputData = new MemoryStream(Encoding.Default.GetBytes(tbInputHash.Text));
            MemoryStream outputData = new MemoryStream();
            
            hash.GetHash(inputData, outputData);
            byte[] buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);

            tbOutHash.Text = Encoding.Default.GetString(buf);
        }

        private void btnSign_Click(object sender, RoutedEventArgs e)
        {
            MemoryStream inputData = new MemoryStream(Encoding.Default.GetBytes(tbInputSign.Text));
            MemoryStream outputData = new MemoryStream();
            byte[] buf;

            SigntureRSA rsa = new SigntureRSA();
            rsa.RSA_Params();
            
            //Stream key = rsa.GetPublicKey();
            //byte[] buf = new byte[key.Length];
            //key.Position = 0;
            //key.Read(buf, 0, buf.Length);
            //tbKeySign.Text = (BitConverter.ToString(buf).Replace('-',' ')).Replace("20", "");

            rsa.SetHashFunction(new MD5());
            rsa.Sign(inputData, outputData);

            buf = new byte[outputData.Length];
            outputData.Position = 0;
            outputData.Read(buf, 0, buf.Length);

            var hexString = BitConverter.ToString(buf);
            hexString = hexString.Replace("-", " ");
            tbOutSign.Text += hexString;
        }

        private void btnVerify_Click(object sender, RoutedEventArgs e)
        {
            byte[] buf = FromHex(tbOutSign.Text);
            if (buf == null)
                return;
            MemoryStream inputData = new MemoryStream(buf);
            MemoryStream outputData = new MemoryStream();         

            SigntureRSA rsa = new SigntureRSA();
            rsa.RSA_Params();
            rsa.SetHashFunction(new MD5());

            if (rsa.Verify(inputData) == true)
                tbOutSign.Text += "\nПодпись верна";
            else
                tbOutSign.Text += "\nПодпись некорректна";
        }
    }
}
