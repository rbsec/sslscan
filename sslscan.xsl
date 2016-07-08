<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
<html>
  <head>
	<link href="janiko.css" rel="stylesheet" type="text/css" />
	<link href='http://fonts.googleapis.com/css?family=PT+Sans:400,400italic,700,700italic' rel='stylesheet' type='text/css' />
  </head>
  <body class='mediawiki skin-janiko'>
  
    <!-- Hostname -->
    <h2><xsl:value-of select="document/ssltest/@host"/>:<xsl:value-of select="document/ssltest/@port"/></h2>
	
	<!-- Compression -->
	<xsl:choose>
	  <xsl:when test="document/ssltest/compression/@supported='0'">
	    <p><xsl:text>La compression TLS n'est pas supportée.</xsl:text></p>
	  </xsl:when>
	  <xsl:when test="document/ssltest/compression/@supported='1'">
	    <p><xsl:text>La compression TLS est supportée.</xsl:text></p>
	  </xsl:when>
	</xsl:choose>
	
	<!-- Renégociation, sécurisée ou pas -->
	<xsl:variable name= "renego" select="document/ssltest/renegotiation/@supported"/>
	<xsl:variable name= "renego_secure" select="document/ssltest/renegotiation/@secure"/>
	<xsl:choose>
	  <xsl:when test="$renego='0'">
	    <p><xsl:text>La renégociation n'est pas supportée.</xsl:text></p>
	  </xsl:when>
	  <xsl:when test="$renego='1'">
	    <p style='display:inline;'><xsl:text>La renégociation est supportée de façon </xsl:text>
		<xsl:choose>
		  <xsl:when test="$renego_secure='0'">
			<div class="invalide"><xsl:text>non sécurisée !</xsl:text></div>
		  </xsl:when>	  
		  <xsl:when test="$renego_secure='1'">
			<div class="valide"><xsl:text>sécurisée.</xsl:text></div>
		  </xsl:when>	  
		</xsl:choose>
		</p>
      </xsl:when>	  
	</xsl:choose>
	
	<!-- Faille heartbleed -->
	<xsl:variable name= "heart_TLS10" select="document/ssltest/heartbleed[@sslversion='TLSv1.0']/@vulnerable"/>
	<xsl:variable name= "heart_TLS11" select="document/ssltest/heartbleed[@sslversion='TLSv1.1']/@vulnerable"/>
	<xsl:variable name= "heart_TLS12" select="document/ssltest/heartbleed[@sslversion='TLSv1.2']/@vulnerable"/>
	<!-- Si vulnérable -->
	<xsl:choose>
		<xsl:when test="$heart_TLS10='1'">
			<div class="invalide">Vulnérable</div> à HeartBleed en TLS 1.0.<br/>
		</xsl:when>
	</xsl:choose>
	<xsl:choose>
		<xsl:when test="$heart_TLS11='1'">
			<div class="invalide">Vulnérable</div> à HeartBleed en TLS 1.1.<br/>
		</xsl:when>
	</xsl:choose>
	<xsl:choose>
		<xsl:when test="$heart_TLS12='1'">
			<div class="invalide">Vulnérable</div> à HeartBleed en TLS 1.2.<br/>
		</xsl:when>
	</xsl:choose>
	<!-- Si pas vulnérable -->
	<xsl:choose>
		<xsl:when test="$heart_TLS10='1'"/>
		<xsl:when test="$heart_TLS11='1'"/>
		<xsl:when test="$heart_TLS12='1'"/>
		<xsl:otherwise>Non vulnérable à la faille HeartBleed.</xsl:otherwise>
	</xsl:choose>



	<!-- Certificat du site -->
	<h4>Certificat</h4>
	<xsl:for-each select="document/ssltest/certificate">
	
		<!-- On examine un certificat -->
		<table class='table_certif'>
			<!-- Sujet -->
			<tr>
				<th style='width:170px;' class='table_certif_head'><xsl:text>Sujet</xsl:text></th>
				<th style='width:700px;'><xsl:value-of select="subject"/></th>
			</tr>
			<!-- Nom(s) alternatif(s) -->
			<xsl:if test="altnames">
				<tr>
					<td class='table_certif_head'><xsl:text>Nom(s) alternatif(s)</xsl:text></td>
					<td><xsl:value-of select="altnames"/></td>
				</tr>
			</xsl:if>
			<!-- Version -->
			<xsl:if test="version">
				<tr>
					<td class='table_certif_head'><xsl:text>Version du certificat</xsl:text></td>
					<td><xsl:value-of select="version"/></td>
				</tr>
			</xsl:if>
			<!-- Numéro de série -->
			<xsl:if test="serial">
				<tr>
					<td class='table_certif_head'><xsl:text>Numéro de série</xsl:text></td>
					<td><xsl:value-of select="serial"/></td>
				</tr>
			</xsl:if>
			<!-- Algorithme de signature -->
			<xsl:if test="signature-algorithm">
				<tr>
					<td class='table_certif_head'><xsl:text>Algorithme de signature</xsl:text></td>
					<td><xsl:value-of select="signature-algorithm"/></td>
				</tr>
			</xsl:if>
			<!-- Algorithme chiffrement de clé -->
			<tr>
				<td class='table_certif_head'><xsl:text>Algorithme chiffrement de clé</xsl:text></td>
				<td><xsl:value-of select="pk/@type"/> sur <xsl:value-of select="pk/@bits"/> bits <xsl:if test="pk-algorithm">(<xsl:value-of select="pk-algorithm"/>)</xsl:if></td>
			</tr>
			<!-- Emetteur du certificat -->
			<tr>
				<td class='table_certif_head'><xsl:text>Emetteur du certificat</xsl:text></td>
				<td><xsl:value-of select="issuer"/></td>
			</tr>
			<!-- Autosigné ? -->
			<tr>
				<td class='table_certif_head'><xsl:text>Certificat autosigné</xsl:text></td>
				<td>
					<xsl:choose>
						<xsl:when test="self-signed='true'">Oui</xsl:when>
						<xsl:when test="self-signed='false'">Non</xsl:when>
						<xsl:otherwise>indéterminé</xsl:otherwise>
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



	<!-- Algos préférés // N'est plus utilisé
	<h4>Algorithmes préférés</h4>
	<table class='table_algos'>
	  <tr>
		<th style="width:80px;" >Version SSL</th>
		<th style="width:300px;">Algorithme</th>
		<th style="width:100px;">Longueur (bits)</th>
	  </tr>
	  <xsl:for-each select="document/ssltest/defaultcipher">
	  <tr>
		<td><xsl:value-of select="@sslversion"/></td>
		<td><xsl:value-of select="@cipher"/></td>
		<td><xsl:value-of select="@bits"/></td>
	  </tr>
	  </xsl:for-each>
	</table>-->
	
	<!-- Algos supportés -->
	<h4>Algorithmes supportés</h4>
	<table class='table_algos'>
	  <tr>
		<th style="width:80px;" >Version SSL</th>
		<th style="width:300px;">Algorithme</th>
		<th style="width:100px;">Longueur (bits)</th>
		<th style="width:80px;" >Statut</th>
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
