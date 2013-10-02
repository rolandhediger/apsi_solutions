package edu.hediger.roland;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.security.auth.x500.X500Principal;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JComboBox;
import javax.swing.JSeparator;

import java.awt.FlowLayout;

import javax.swing.JTextPane;

import java.awt.GridLayout;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import javax.swing.BoxLayout;


import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class MainWindow extends JFrame {

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainWindow frame = new MainWindow();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	private JTextPane textPane;
	private KeyPair keypair;
	private BigInteger serialNumber;
	private PrivateKey javaPrivateKey;
	private X509Certificate cert;

	/**
	 * Create the frame.
	 */
	public MainWindow() {
		setTitle("APSI U1");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		JPanel contentPane = new JPanel();
		this.setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));

		JPanel panel = new JPanel();
		contentPane.add(panel, BorderLayout.NORTH);
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		JButton btnGenerateCertificate = new JButton("Generate Certificate");
		btnGenerateCertificate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				generateCertificate();
			}
		});
		panel.add(btnGenerateCertificate);

		JSeparator separator = new JSeparator();
		panel.add(separator);

		JButton btnSave = new JButton("Save ");
		
		panel.add(btnSave);

		JSeparator separator_1 = new JSeparator();
		panel.add(separator_1);

		JLabel lblFormat = new JLabel("Format:");
		panel.add(lblFormat);

		final JComboBox comboBox = new JComboBox();
		panel.add(comboBox);
		comboBox.addItem("PEM");
		comboBox.addItem("DER");
		comboBox.addItem("PKCS12");
		comboBox.addItem("PKCS7");
		btnSave.addActionListener(new ActionListener() {
			private String pemFile;

			public void actionPerformed(ActionEvent arg0) {
				int sel = comboBox.getSelectedIndex();
				switch (sel) {
				case 0:
				   StringWriter sw = new StringWriter();
					PEMWriter writer = new PEMWriter(sw);
					try {
						writer.writeObject(cert);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					print("PEM");
					print(sw.toString());
					pemFile = sw.toString();
					break;
				case 1:
					String base64 = new String(pemFile).replaceAll("\\s", ""); 
					base64 = base64.replace("-----BEGINPKCS7-----", ""); 
					base64 = base64.replace("-----ENDPKCS7-----", ""); 
					String derFile = org.bouncycastle.util.encoders.Base64.decode(base64.getBytes()).toString();
					print("DER");
					print(derFile);
					break;
				case 2:
					Certificate[] chain = new Certificate[1];
					chain[0] = cert;
					char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
					
					 PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)keypair.getPrivate();
					 bagAttr.setBagAttribute(
							                 PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
							                 new DERBMPString("Roland's Key"));
					try {
						bagAttr.setBagAttribute(
						     PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
						    new SubjectKeyIdentifierStructure(keypair.getPublic()));
						 KeyStore store = KeyStore.getInstance("PKCS12", "BC");
			             store.load(null, null);
			             store.setKeyEntry("Roland's Key", keypair.getPrivate(), null, chain);
			             ByteArrayOutputStream baos  = new ByteArrayOutputStream();
			             store.store(baos, passwd);
			             print("PKCS12");
			             print(baos.toString());
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (KeyStoreException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchProviderException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CertificateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
							            
							             
					break;
				case 3:
					print ("PKCS7");
					try {
						print(encryptCertToPKCS7(cert, keypair.getPrivate()).toString());
					} catch (CertificateEncodingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchProviderException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (OperatorCreationException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CMSException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					break;

				default:
					break;
				}
			}
		});
		

		textPane = new JTextPane();
		contentPane.add(textPane, BorderLayout.CENTER);
		print("Welcome to my certificate generator");
	}

	public void print(String input) {
		String currentText = textPane.getText();
		textPane.setText(currentText + "\n" + input);

	}
	  private byte[] encryptCertToPKCS7(X509Certificate certificate, Key key) 
              throws CertificateEncodingException, CMSException, NoSuchProviderException, NoSuchAlgorithmException, IOException, OperatorCreationException {
      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
      ArrayList<Certificate> chain = new ArrayList<Certificate>();
      chain.add(cert);
      ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build((PrivateKey) key);
      generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                                                                             .setProvider("BC").build())
                                                                            .build(sha256Signer, certificate));
      generator.addCertificates(new JcaCertStore(chain));
      CMSTypedData content = new CMSProcessableByteArray(certificate.getEncoded());

      CMSSignedData signedData = generator.generate(content, true);
      return signedData.getEncoded();
  }

	public void generateCertificate() {
		Security.addProvider(new BouncyCastleProvider());
		 BigInteger serialNumber = BigInteger.probablePrime(1024, new Random());
		generateRSAKeys();
		String details = "CN=Roland Hediger,O=FHNW,OU=NS,C=Schweiz,L=Windisch,ST=Aargau";
		java.util.Date startDate = Calendar.getInstance().getTime(); // time
																		// from
																		// which
																		// certificate
																		// is
																		// valid
		java.util.Date expiryDate = new java.util.Date("2015/01/01"); // time
																		// after
																		// which
																		// certificate
																		// is
																		// not
																		// valid
		

		X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
		gen.setIssuerDN(new X500Principal(details));;
		gen.setSubjectDN(new X500Principal(details));
		gen.setSerialNumber(serialNumber);
		gen.setNotBefore(startDate);
		gen.setNotAfter(expiryDate);
		gen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		gen.setPublicKey(keypair.getPublic());
		try {
			cert = gen.generate(keypair.getPrivate(),"BC");
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		print("Certificate generated in memory");
		
	}



	public void generateRSAKeys() {
		   KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			   keyPairGenerator.initialize(1024, new SecureRandom());
			    this.keypair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		print("Generated  RSA keyPair");
	

	}

}
