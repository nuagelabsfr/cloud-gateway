<?xml version="1.0" encoding="iso-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" >

  <xsl:output  method="text"
               encoding="utf-8" />

  <xsl:template match="Parameter">
    <xsl:text>\subsection*{</xsl:text>
    <xsl:value-of select="Name" />
    <xsl:text>}
    </xsl:text>
    <xsl:text>\label{config:</xsl:text>
    <xsl:value-of select="Name" />
    <xsl:text>}
    </xsl:text>

    <xsl:text>\begin{itemize}
    </xsl:text>

    <xsl:apply-templates select="Context|Required|Default|PossibleValues|Example" />

    <xsl:text>\end{itemize}
    </xsl:text>

    <xsl:apply-templates select="Description" />

  </xsl:template>

  <xsl:template match="Context">
    <xsl:text>\item Context: </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>
    </xsl:text>
  </xsl:template>

  <xsl:template match="Required">
    <xsl:text>\item Required: </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>
    </xsl:text>
  </xsl:template>

  <xsl:template match="Default">
    <xsl:text>\item Default: </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>
    </xsl:text>
  </xsl:template>

  <xsl:template match="PossibleValues">
    <xsl:text>\item Possible Values: </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>
    </xsl:text>
  </xsl:template>

  <xsl:template match="Example">
    <xsl:text>\item \textit{Example: </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>}
    </xsl:text>
  </xsl:template>

  <xsl:template match="Description">
    <xsl:text>\hspace{0pt}\newline
    </xsl:text>
    <xsl:value-of select="." />
    <xsl:text>
    </xsl:text>
  </xsl:template>

</xsl:stylesheet>
