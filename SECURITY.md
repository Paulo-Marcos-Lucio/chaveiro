<p align="center"><a href="SECURITY.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/chaveiro/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Política de Segurança

## Versões suportadas

Correções de segurança são aplicadas à linha de release mais recente (`0.1.x`) e à `main`. Versões anteriores não recebem retrofix — atualize para a última.

## Divulgação responsável

Reporte vulnerabilidades **de forma privada** para **contatopml26@gmail.com** (assunto com prefixo `[security]`). Descreva o impacto e um passo a passo de reprodução. Dê um prazo razoável para correção antes de divulgar publicamente; crédito ao relator é dado por padrão, salvo pedido em contrário.

## Uso ético

O Chaveiro inclui ferramentas ofensivas (`crack`, `forge`, `forge-confusion`) destinadas a **testar sistemas que você possui ou tem autorização explícita e por escrito para avaliar**. O propósito é defensivo: comprovar uma falha para justificar a correção.

No Brasil, o acesso não autorizado a dispositivo informático é crime (Lei 12.737/2012, agravada pela Lei 14.155/2021). Use sempre com escopo e autorização definidos.

## Modelo de ameaças da suíte

Como a suíte AppSec se defende de um alvo hostil — e o que ainda não está fechado — está documentado em [`modelo-de-ameacas.md`](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/modelo-de-ameacas.md), no repositório da [Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela): é ela quem tem superfície de rede (fala HTTP com o alvo escolhido pelo operador). O Chaveiro audita um token que o operador fornece (decodificado sem verificar assinatura, sem tocar a rede na auditoria) — a superfície de "resposta hostil de um alvo remoto" não se aplica a ele do mesmo jeito.
