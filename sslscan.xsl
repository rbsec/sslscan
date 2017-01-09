<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:my="my:my" exclude-result-prefixes="my">

	<xsl:param name="pLang" select="'en'"/>
	<my:texts>
		<dot>.</dot>
		<pageTitle lang="en">This is the title in English</pageTitle>
		<pageTitle lang="fr">Titre en français</pageTitle>
		<enabled lang="en">enabled</enabled>
		<enabled lang="fr">activé</enabled>
		<disabled lang="en">disabled</disabled>
		<disabled lang="fr">inactive</disabled>
		<secure lang="en">secure</secure>
		<secure lang="fr">sécurisée</secure>
		<unsecure lang="en">unsecure</unsecure>
		<unsecure lang="fr">non sécurisée</unsecure>
		<vulnerable lang="en">Vulnerable</vulnerable>
		<vulnerable lang="fr">Vulnérable</vulnerable>
		<notVulnerable lang="en">Not vulnerable</notVulnerable>
		<notVulnerable lang="fr">Non vulnérable</notVulnerable>
		<compTLS lang="en">TLS compression is </compTLS>
		<compTLS lang="fr">La compression TLS est </compTLS>
		<negoNotSupported lang="en">Renegociation is not supported.</negoNotSupported>
		<negoNotSupported lang="fr">La renégociation n'est pas supportée.</negoNotSupported>
		<negoSupported lang="en">Renegociation is supported but it's </negoSupported>
		<negoSupported lang="fr">La renégociation est supportée de façon </negoSupported>
		<SSLVersion lang="en">SSL Version</SSLVersion>
		<SSLVersion lang="fr">Version SSL</SSLVersion>
		<algo lang="en">Algorithm</algo>
		<algo lang="fr">Algorithme</algo>
		<length lang="en">Length (bits)</length>
		<length lang="fr">Longueur (bits)</length>
		<status lang="en">Status</status>
		<status lang="fr">Statut</status>
		<certificate lang="en">Certificate</certificate>
		<certificate lang="fr">Certificat</certificate>
		<supportedAlgos lang="en">Supported algorithms</supportedAlgos>
		<supportedAlgos lang="fr">Algorithmes supportés</supportedAlgos>
		<subject lang="en">Subject</subject>
		<subject lang="fr">Sujet</subject>
		<altName lang="en">Alternative(s) Name(s)</altName>
		<altName lang="fr">Nom(s) alternatif(s)</altName>
		<issuer lang="en">Issuer</issuer>
		<issuer lang="fr">Emetteur du certificat</issuer>
		<signAlgo lang="en">Signature algorithm</signAlgo>
		<signAlgo lang="fr">Algorithme de signature</signAlgo>
		<pkAlgo lang="en">Private key algorithm</pkAlgo>
		<pkAlgo lang="fr">Algorithme chiffrement de la clé</pkAlgo>
		<SN lang="en">Serial number</SN>
		<SN lang="fr">Numéro de série</SN>
		<certVersion lang="en">Certificate version</certVersion>
		<certVersion lang="fr">Version du certificat</certVersion>
		<selfSign lang="en">Self-signed</selfSign>
		<selfSign lang="fr">Auto-signé </selfSign>
		<heartbleed lang="en"> to Heartbleed</heartbleed>
		<heartbleed lang="fr"> à Heartbleed</heartbleed>
		<for lang="en"> for </for>
		<for lang="fr"> en </for>
		<yes lang="en">yes</yes>
		<yes lang="fr">oui</yes>
		<no lang="en">no</no>
		<no lang="fr">non</no>
		<unknown lang="en">unknown</unknown>
		<unknown lang="fr">indeterminé</unknown>
		<preferred lang="en">preferred</preferred>
		<preferred lang="fr">préféré</preferred>
		<accepted lang="en">accepted</accepted>
		<accepted lang="fr">accepté</accepted>
	</my:texts>
	<xsl:variable name="vTexts" select="document('')/*/my:texts"/>


<xsl:template match="/">

<html>
  <head>
	<link href="sslscan.css" rel="stylesheet" type="text/css" />
	<!-- If you want your own Google Font...-->
	<link href='http://fonts.googleapis.com/css?family=PT+Sans:400,400italic,700,700italic' rel='stylesheet' type='text/css' />
  </head>
  <body class='mediawiki skin-janiko'>

	<title>
		<xsl:value-of select="$vTexts/pageTitle[@lang = $pLang]"/>
	</title>

    <!-- Hostname -->
    <h2><xsl:value-of select="document/ssltest/@host"/>:<xsl:value-of select="document/ssltest/@port"/></h2>
	
	<!-- Compression -->
	<p>
		<xsl:value-of select="$vTexts/compTLS[@lang = $pLang]"/>
		<xsl:choose>
			<xsl:when test="document/ssltest/compression/@supported='0'">
				<xsl:value-of select="$vTexts/enabled[@lang = $pLang]"/>
			</xsl:when>
			<xsl:when test="document/ssltest/compression/@supported='1'">
				<xsl:value-of select="$vTexts/disabled[@lang = $pLang]"/>
			</xsl:when>
		</xsl:choose>
		<xsl:value-of select="$vTexts/dot"/>
	</p>
	
	<!-- Renégociation, sécurisée ou pas -->
	<p>
	<xsl:variable name= "renego" select="document/ssltest/renegotiation/@supported"/>
	<xsl:variable name= "renego_secure" select="document/ssltest/renegotiation/@secure"/>
	<xsl:choose>
	  <xsl:when test="$renego='0'">
	    <xsl:value-of select="$vTexts/negoNotSupported[@lang = $pLang]"/>
	  </xsl:when>
	  <xsl:when test="$renego='1'">
		<div class="inline"><!-- do not remove ; needed for IE11 -->
	    <xsl:value-of select="$vTexts/negoSupported[@lang = $pLang]"/>
		<xsl:choose>
		  <xsl:when test="$renego_secure='0'">
			<div class="inline red"><xsl:value-of select="$vTexts/unsecure[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/dot"/>
		  </xsl:when>	  
		  <xsl:when test="$renego_secure='1'">
			<div class="inline green"><xsl:value-of select="$vTexts/secure[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/dot"/>
		  </xsl:when>	  
		</xsl:choose>
		</div>
      </xsl:when>	  
	</xsl:choose>
	</p>
	
	<!-- Heartbleed -->
	<xsl:variable name= "heart_TLS10" select="document/ssltest/heartbleed[@sslversion='TLSv1.0']/@vulnerable"/>
	<xsl:variable name= "heart_TLS11" select="document/ssltest/heartbleed[@sslversion='TLSv1.1']/@vulnerable"/>
	<xsl:variable name= "heart_TLS12" select="document/ssltest/heartbleed[@sslversion='TLSv1.2']/@vulnerable"/>
	<!-- Vulnerable ? -->
	<p style='display:inline;'>
	<xsl:choose>
		<xsl:when test="$heart_TLS10='1'">
			<div class="red inline"><xsl:value-of select="$vTexts/vulnerable[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/heartbleed[@lang = $pLang]"/><xsl:value-of select="$vTexts/for[@lang = $pLang]"/>TLS 1.0.
		</xsl:when>
	</xsl:choose>
	<xsl:choose>
		<xsl:when test="$heart_TLS11='1'">
			<div class="red inline"><xsl:value-of select="$vTexts/vulnerable[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/heartbleed[@lang = $pLang]"/><xsl:value-of select="$vTexts/for[@lang = $pLang]"/>TLS 1.1.
		</xsl:when>
	</xsl:choose>
	<xsl:choose>
		<xsl:when test="$heart_TLS12='1'">
			<div class="red inline"><xsl:value-of select="$vTexts/vulnerable[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/heartbleed[@lang = $pLang]"/><xsl:value-of select="$vTexts/for[@lang = $pLang]"/>TLS 1.2.
		</xsl:when>
	</xsl:choose>
	<!-- If not vulnerable -->
	<xsl:choose>
		<xsl:when test="$heart_TLS10='1'"/>
		<xsl:when test="$heart_TLS11='1'"/>
		<xsl:when test="$heart_TLS12='1'"/>
		<xsl:otherwise>
		<div class="green inline"><xsl:value-of select="$vTexts/notVulnerable[@lang = $pLang]"/></div><xsl:value-of select="$vTexts/heartbleed[@lang = $pLang]"/><xsl:value-of select="$vTexts/dot"/>
		</xsl:otherwise>
	</xsl:choose>
	</p>


	<!-- Certificate -->
	<h4><xsl:value-of select="$vTexts/certificate[@lang = $pLang]"/></h4>
	<xsl:for-each select="document/ssltest/certificate">
	
		<!-- Looking at the certificate -->
		<table class='table_certif'>
			<!-- Sujet -->
			<tr>
				<th class='col-250 table_certif_head'><xsl:value-of select="$vTexts/subject[@lang = $pLang]"/></th>
				<th style='col-700'><xsl:value-of select="subject"/></th>
			</tr>
			<!-- Nom(s) alternatif(s) -->
			<xsl:if test="altnames">
				<tr>
					<td class='table_certif_head'><xsl:value-of select="$vTexts/altName[@lang = $pLang]"/></td>
					<td><xsl:value-of select="altnames"/></td>
				</tr>
			</xsl:if>
			<!-- Version -->
			<xsl:if test="version">
				<tr>
					<td class='table_certif_head'><xsl:value-of select="$vTexts/certVersion[@lang = $pLang]"/></td>
					<td><xsl:value-of select="version"/></td>
				</tr>
			</xsl:if>
			<!-- Serial number -->
			<xsl:if test="serial">
				<tr>
					<td class='table_certif_head'><xsl:value-of select="$vTexts/SN[@lang = $pLang]"/></td>
					<td><xsl:value-of select="serial"/></td>
				</tr>
			</xsl:if>
			<!-- Signature Algo -->
			<xsl:if test="signature-algorithm">
				<tr>
					<td class='table_certif_head'><xsl:value-of select="$vTexts/signAlgo[@lang = $pLang]"/></td>
					<td><xsl:value-of select="signature-algorithm"/></td>
				</tr>
			</xsl:if>
			<!-- Private Key Algo -->
			<tr>
				<td class='table_certif_head'><xsl:value-of select="$vTexts/pkAlgo[@lang = $pLang]"/></td>
				<td><xsl:value-of select="pk/@type"/>/<xsl:value-of select="pk/@bits"/> bits <xsl:if test="pk-algorithm">(<xsl:value-of select="pk-algorithm"/>)</xsl:if></td>
			</tr>
			<!-- Issuer -->
			<tr>
				<td class='table_certif_head'><xsl:value-of select="$vTexts/issuer[@lang = $pLang]"/></td>
				<td><xsl:value-of select="issuer"/></td>
			</tr>
			<!-- Self-signed? -->
			<tr>
				<td class='table_certif_head'><xsl:value-of select="$vTexts/selfSign[@lang = $pLang]"/>?</td>
				<td>
					<xsl:choose>
						<xsl:when test="self-signed='true'"><xsl:value-of select="$vTexts/yes[@lang = $pLang]"/></xsl:when>
						<xsl:when test="self-signed='false'"><xsl:value-of select="$vTexts/no[@lang = $pLang]"/></xsl:when>
						<xsl:otherwise><xsl:value-of select="$vTexts/unknown[@lang = $pLang]"/></xsl:otherwise>
					</xsl:choose>
				</td>
			</tr>
			<!-- Extensions x509 -->
			<xsl:for-each select="X509v3-Extensions/extension">
			<tr>
				<td><xsl:value-of select="@name"/></td>
				<td><xsl:value-of select="."/></td>
			</tr>
			</xsl:for-each>
			
		</table>
		<p/>
	</xsl:for-each>
	
	<p/>

	
	<!-- Algos supportés -->
	<h4><xsl:value-of select="$vTexts/supportedAlgos[@lang = $pLang]"/></h4>
	<table class='table_algos'>
	  <tr>
		<th style="width:120px;" ><xsl:value-of select="$vTexts/SSLVersion[@lang = $pLang]"/></th>
		<th style="width:320px;"><xsl:value-of select="$vTexts/algo[@lang = $pLang]"/></th>
		<th style="width:120px;"><xsl:value-of select="$vTexts/length[@lang = $pLang]"/></th>
		<th style="width:80px;" ><xsl:value-of select="$vTexts/status[@lang = $pLang]"/></th>
	  </tr>
	  <xsl:for-each select="document/ssltest/cipher">
	  <tr>
		<xsl:choose>
			<xsl:when test="@algo-safety='yellow'">
				<td class='yellow'><xsl:value-of select="@sslversion"/></td>
			</xsl:when>
			<xsl:otherwise>
				<td class='grey'><xsl:value-of select="@sslversion"/></td>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:choose>
			<xsl:when test="@overall-safety='red'">
				<td class='red'><xsl:value-of select="@cipher"/></td>
			</xsl:when>
			<xsl:when test="@overall-safety='green'">
				<td class='green'><xsl:value-of select="@cipher"/></td>
			</xsl:when>
			<xsl:when test="@overall-safety='purple'">
				<td class='purple'><xsl:value-of select="@cipher"/></td>
			</xsl:when>
			<xsl:when test="@overall-safety='yellow'">
				<td class='yellow'><xsl:value-of select="@cipher"/></td>
			</xsl:when>
			<xsl:otherwise>
				<td class='grey'><xsl:value-of select="@cipher"/></td>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:choose>
			<xsl:when test="@length-safety='green'">
				<td class='green'><xsl:value-of select="@bits"/></td>
			</xsl:when>
			<xsl:otherwise>
				<td class='grey'><xsl:value-of select="@bits"/></td>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:choose>
			<xsl:when test="@status='preferred'">
				<td class='green'><xsl:value-of select="@status"/></td>
			</xsl:when>
			<xsl:otherwise>
				<td class='grey'><xsl:value-of select="@status"/></td>
			</xsl:otherwise>
		</xsl:choose>
	  </tr>
	  </xsl:for-each>
	</table>

	</body>
</html>
</xsl:template>
</xsl:stylesheet>