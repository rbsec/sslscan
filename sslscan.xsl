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

	<!-- Algos préférés -->
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
	</table>
	
	<!-- Algos supportés -->
	<h4>Algorithmes supportés</h4>
	<table class='table_algos'>
	  <tr>
		<th style="width:80px;" >Version SSL</th>
		<th style="width:300px;">Algorithme</th>
		<th style="width:100px;">Longueur (bits)</th>
	  </tr>
	  <xsl:for-each select="document/ssltest/cipher">
	  <tr>
		<td><xsl:value-of select="@sslversion"/></td>
		<xsl:choose>
		<xsl:when test="@safety-level='red_bg'">
			<td class='red_bg'><xsl:value-of select="@cipher"/></td>
		</xsl:when>
		<xsl:when test="@safety-level='red'">
			<td class='red'><xsl:value-of select="@cipher"/></td>
		</xsl:when>
		<xsl:when test="@safety-level='green'">
			<td class='green'><xsl:value-of select="@cipher"/></td>
		</xsl:when>
		<xsl:when test="@safety-level='purple'">
			<td class='purple'><xsl:value-of select="@cipher"/></td>
		</xsl:when>
		<xsl:when test="@safety-level='yellow'">
			<td class='yellow'><xsl:value-of select="@cipher"/></td>
		</xsl:when>
		<xsl:otherwise>
			<td class='gray'><xsl:value-of select="@cipher"/></td>
		</xsl:otherwise>
		</xsl:choose>
		<td><xsl:value-of select="@bits"/></td>
	  </tr>
	  </xsl:for-each>
	</table>

	</body>
</html>
</xsl:template>
</xsl:stylesheet>
