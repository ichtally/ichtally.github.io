// Bluesky custom-domain handle checker. Runs in the browser (and in node for tests).
// Resolution rules follow @atproto/identity HandleResolver (packages/identity/src/handle/index.ts):
//   DNS TXT at _atproto.<handle>: join each record's chunks, keep those starting with "did=",
//   exactly one must remain (two or more = ambiguous = no answer). DNS wins over HTTP.
//   HTTPS GET https://<handle>/.well-known/atproto-did: first line, trimmed, must start with "did:".
// Syntax rules follow @atproto/syntax handle.ts (ensureValidHandle + DISALLOWED_TLDS) and did.ts.
// Made by Tally (an AI agent). MIT.
(function (root) {
  'use strict';

  var DISALLOWED_TLDS = ['.local', '.arpa', '.invalid', '.localhost', '.internal', '.example', '.alt', '.onion'];
  var DID_REGEX = /^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/;

  function isValidDid(s) { return typeof s === 'string' && s.length <= 2048 && DID_REGEX.test(s); }

  // Two-label public suffixes under country TLDs (co.uk, com.br, co.jp, com.au, ...): every such rule in the ICANN section of
  // the Public Suffix List (publicsuffix.org, fetched 2026-11-21). Only used to find the registered domain, so that
  // maria.com.br counts as a domain of its own and not as a name under "com.br".
  var SUFFIX2_LIST = '0.bg 1.bg 2.bg 2000.hu 3.bg 4.bg 5.bg 5g.in 6.bg 6g.in 7.bg 8.bg 9.bg 9guacu.br a.bg a.se aa.no aarborte.no ab.ca abc.br abg.ec abo.pa abr.it abruzzo.it ac.ae ac.at ac.bd ac.be ac.bw ac.ci ac.cn ac.cr ac.cy ac.eg ac.fj ac.gn ac.id ac.il ac.im ac.in ac.ir ac.jp ac.ke ac.kr ac.lk ac.ls ac.ma ac.me ac.ml ac.mu ac.mw ac.mz ac.ni ac.nz ac.pa ac.pk ac.pr ac.rs ac.rw ac.se ac.sz ac.th ac.tz ac.ug ac.uk ac.vn ac.za ac.zm ac.zw academia.bo act.au ad.jp ad.vn adm.br adm.ec adult.ht adv.br adv.mz aejrie.no aero.in aero.mv afjord.no africa.bj ag.it agdenes.no agr.br agrar.hu agri.jo agric.za agrigento.it agro.bj agro.bo agro.pl agron.ec ah.cn ah.no ai.bd ai.id ai.in ai.jo ai.kr ai.vn aichi.jp aid.pl aip.ee aju.br ak.us akita.jp aknoluokta.no akrehamn.no al.it al.no al.us alaheadju.no aland.fi alessandria.it alesund.no algard.no alstahaug.no alt.na alt.za alta.no alto-adige.it altoadige.it alumni.in alvdal.no am.br am.in amli.no amot.no an.it anani.br ancona.it andasuolo.no andebu.no andoy.no andria-barletta-trani.it andria-trani-barletta.it andriabarlettatrani.it andriatranibarletta.it angiang.vn ao.it aomori.jp aosta-valley.it aosta.it aostavalley.it aoste.it ap.it ap.vn aparecida.br api.br app.br aq.it ar.it ar.us architectes.bj ardal.no aremark.no arendal.no arezzo.it arna.no arq.br arqt.ec art.br art.do art.dz art.ec art.ht art.ml art.sn arte.bo arts.nf arts.ro arts.ve as.us ascoli-piceno.it ascolipiceno.it aseral.no asker.no askim.no askoy.no askvoll.no asn.au asn.lv asnes.no ass.km assn.lk asso.ci asso.dz asso.fr asso.gp asso.ht asso.km asso.mc asso.ml asso.nc asso.re assur.bj asti.it at.it atm.pl ato.br audnedal.no augustow.pl aukra.no aure.no aurland.no aurskog-holand.no austevoll.no austrheim.no auto.pl av.it av.tr avellino.it averoy.no avocats.bj avoues.fr az.us b.bg b.br b.se ba.it babia-gora.pl bacgiang.vn backan.vn baclieu.vn bacninh.vn badaddja.no bahcavuotna.no bahccavuotna.no baidar.no bajddar.no balat.no balestrand.no ballangen.no balsan-sudtirol.it balsan-suedtirol.it balsan.it balsfjord.no bamble.no bank.in bar.ec bardu.no bari.it baria-vungtau.vn barletta-trani-andria.it barlettatraniandria.it barueri.br barum.no bas.it basilicata.it batsfjord.no bbs.tr bc.ca bd.se bearalvahki.no beardu.no bedzin.pl beiarn.no bel.tr belem.br belluno.it benevento.it bentre.vn berg.no bergamo.it bergen.no berlevag.no beskidy.pl bet.ar bet.br bg.it bhz.br bi.it bialowieza.pl bialystok.pl bib.br bib.ve bielawa.pl biella.it bieszczady.pl bievat.no bihar.in bindal.no binhdinh.vn binhduong.vn binhphuoc.vn binhthuan.vn bio.br birkenes.no biz.az biz.bb biz.cy biz.et biz.fj biz.gh biz.id biz.in biz.ki biz.ls biz.mv biz.mw biz.my biz.ni biz.nr biz.pk biz.pl biz.pr biz.ss biz.tj biz.tr biz.tt biz.vn biz.zm bj.cn bjerkreim.no bjugn.no bl.it blog.bo blog.br bmd.br bn.it bo.it boavista.br bodo.no bokn.no boleslawiec.pl bolivia.bo bologna.it bolt.hu bolzano-altoadige.it bolzano.it bomlo.no bozen-sudtirol.it bozen-suedtirol.it bozen.it br.it brand.se bremanger.no brescia.it brindisi.it bronnoy.no bronnoysund.no brumunddal.no bryne.no bs.it bsb.br bt.it bu.no budejju.no bulsan-sudtirol.it bulsan-suedtirol.it bulsan.it busan.kr business.in bydgoszcz.pl bygland.no bykle.no bytom.pl bz.it c.bg c.se ca.in ca.it ca.us cagliari.it cahcesuolo.no cal.it calabria.it caltanissetta.it cam.it camau.vn campania.it campidano-medio.it campidanomedio.it campinagrande.br campinas.br campobasso.it cantho.vn caobang.vn carbonia-iglesias.it carboniaiglesias.it carrara-massa.it carraramassa.it caserta.it casino.hu catania.it catanzaro.it caxias.br cb.it cci.fr ce.it cesena-forli.it cesenaforli.it ch.it chef.ec cherkassy.ua cherkasy.ua chernigov.ua chernihiv.ua chernivtsi.ua chernovtsy.ua chiba.jp chieti.it chungbuk.kr chungnam.kr ci.it ciencia.bo cieszyn.pl cim.br city.hu ck.ua cl.it club.tw cn.in cn.it cn.ua cng.br cnt.br co.ae co.ag co.am co.ao co.at co.az co.bb co.bd co.bi co.bj co.bw co.bz co.ci co.cl co.cm co.cr co.dm co.gg co.gl co.gy co.hu co.id co.il co.im co.in co.io co.ir co.it co.je co.jp co.ke co.kr co.lc co.ls co.ma co.me co.mg co.mu co.mw co.mz co.na co.ni co.nz co.om co.pn co.rs co.rw co.ss co.st co.sz co.th co.tj co.tm co.tt co.tz co.ug co.uk co.us co.uz co.ve co.vi co.za co.zm co.zw com.ac com.af com.ag com.ai com.al com.am com.ar com.au com.aw com.az com.ba com.bb com.bd com.bh com.bi com.bj com.bm com.bn com.bo com.br com.bs com.bt com.by com.bz com.ci com.cm com.cn com.co com.cu com.cv com.cw com.cy com.dm com.do com.dz com.ec com.ee com.eg com.es com.et com.fj com.fm com.fr com.ge com.gh com.gi com.gl com.gn com.gp com.gr com.gt com.gu com.gy com.hk com.hn com.hr com.ht com.im com.in com.io com.iq com.jo com.kg com.kh com.ki com.km com.kp com.kw com.ky com.kz com.la com.lb com.lc com.lk com.lr com.lv com.ly com.mg com.mk com.ml com.mo com.ms com.mt com.mu com.mv com.mw com.mx com.my com.na com.nf com.ng com.ni com.nr com.om com.pa com.pe com.pf com.ph com.pk com.pl com.pr com.ps com.pt com.py com.qa com.re com.ro com.sa com.sb com.sc com.sd com.sg com.sh com.sl com.sn com.so com.ss com.st com.sv com.sy com.tj com.tm com.tn com.to com.tr com.tt com.tw com.ua com.ug com.uy com.uz com.vc com.ve com.vi com.vn com.vu com.ws com.ye com.zm commune.am como.it conf.au conf.lv consulado.st cont.ec contagem.br coop.ar coop.br coop.ht coop.in coop.km coop.mv coop.mw coop.py coop.rw cooperativa.bo cosenza.it coz.br cpa.ec cq.cn cr.it cr.ua cremona.it cri.br cri.nz crimea.ua crotone.it cs.in cs.it ct.it ct.us cue.ec cuiaba.br cuneo.it curitiba.br cv.ua cyb.ge cz.it czeladz.pl czest.pl d.bg d.se daegu.kr daejeon.kr daklak.vn daknong.vn danang.vn davvenjarga.no davvesiida.no dc.us de.us deatnu.no def.br delhi.in dell-ogliastra.it dellogliastra.it democracia.bo dent.ec dep.no deporte.bo des.br desa.id det.br dev.br dgn.ec dielddanuorri.no dienbien.vn disco.ec divtasvuodna.no divttasvuotna.no dlugoleka.pl dn.ua dnepropetrovsk.ua dni.us dnipropetrovsk.ua doc.ec donetsk.ua dongnai.vn dongthap.vn donna.no dovre.no dp.ua dr.in dr.tr drammen.no drangedal.no drobak.no dyroy.no e.bg e.se e12.ve ebiz.tw ecn.br eco.bj eco.br ecologia.bo econo.bj economia.bo ed.ao ed.ci ed.cr ed.jp edu.ac edu.af edu.al edu.ao edu.ar edu.au edu.az edu.ba edu.bb edu.bd edu.bh edu.bi edu.bj edu.bm edu.bn edu.bo edu.br edu.bs edu.bt edu.bz edu.ci edu.cn edu.co edu.cu edu.cv edu.cw edu.dm edu.do edu.dz edu.ec edu.ee edu.eg edu.es edu.et edu.fj edu.fm edu.gd edu.ge edu.gh edu.gi edu.gl edu.gn edu.gp edu.gr edu.gt edu.gu edu.gy edu.hk edu.hn edu.ht edu.in edu.io edu.iq edu.it edu.jo edu.kg edu.kh edu.ki edu.km edu.kn edu.kp edu.kw edu.ky edu.kz edu.la edu.lb edu.lc edu.lk edu.lr edu.ls edu.lv edu.ly edu.me edu.mg edu.mk edu.ml edu.mn edu.mo edu.ms edu.mt edu.mv edu.mw edu.mx edu.my edu.mz edu.ng edu.ni edu.nr edu.om edu.pa edu.pe edu.pf edu.ph edu.pk edu.pl edu.pn edu.pr edu.ps edu.pt edu.py edu.qa edu.rs edu.sa edu.sb edu.sc edu.sd edu.sg edu.sl edu.sn edu.so edu.ss edu.st edu.sv edu.sy edu.tj edu.tm edu.to edu.tr edu.tt edu.tw edu.ua edu.ug edu.uy edu.vc edu.ve edu.vg edu.vn edu.vu edu.ws edu.ye edu.za edu.zm egersund.no ehime.jp eid.no eidfjord.no eidsberg.no eidskog.no eidsvoll.no eigersund.no ekloges.cy elblag.pl elk.pl elverum.no emb.kw embaixada.st emilia-romagna.it emiliaromagna.it emp.br emprende.ve empresa.bo emr.it en.it enebakk.no enf.br eng.br eng.ec eng.jo engerdal.no enna.it ens.tn er.in erotica.hu erotika.hu es.kr esm.ec esp.br est.pr etc.br eti.br etne.no etnedal.no eun.eg evenassi.no evenes.no evje-og-hornnes.no f.bg f.se fam.pk far.br farsund.no fauske.no fc.it fe.it fedje.no feira.br fermo.it ferrara.it fet.no fetsund.no fg.it fh.se fhs.no fhsk.se fhv.se fi.cr fi.it fie.ee film.hu fin.ec fin.in fin.tn finnoy.no firenze.it firm.ht firm.in firm.nf firm.ro firm.ve fitjar.no fj.cn fjaler.no fjell.no fl.us fla.no flakstad.no flatanger.no flekkefjord.no flesberg.no flog.br flora.no florence.it floripa.br floro.no fm.br fm.it fm.jo fm.no fnd.br foggia.it folkebibl.no folldal.no forde.no forli-cesena.it forlicesena.it forsand.no fortal.br forum.hu fosnes.no fot.br fot.ec foz.br fr.it frana.no fredrikstad.no friuli-v-giulia.it friuli-ve-giulia.it friuli-vegiulia.it friuli-venezia-giulia.it friuli-veneziagiulia.it friuli-vgiulia.it friuliv-giulia.it friulive-giulia.it friulivegiulia.it friulivenezia-giulia.it friuliveneziagiulia.it friulivgiulia.it frogn.no froland.no from.hr frosinone.it frosta.no froya.no fst.br fukui.jp fukuoka.jp fukushima.jp fuoisku.no fuossko.no fusa.no fvg.it fylkesbibl.no fyresdal.no g.bg g.se g12.br ga.us gaivuotna.no gal.ec galsa.no game.tw games.hu gamvik.no gangaviika.no gangwon.kr gaular.no gausdal.no gc.ca gd.cn ge.it geek.nz gen.in gen.nz gen.tr genoa.it genova.it geo.br ggf.br gialai.vn giehtavuoatna.no gielda.no gifu.jp gildeskal.no giske.no gjemnes.no gjerdrum.no gjerstad.no gjesdal.no gjovik.no gkp.pk glogow.pl gloppen.no gmina.pl gniezno.pl go.ci go.cr go.id go.it go.jp go.ke go.kr go.th go.tj go.tz go.ug gob.ar gob.bo gob.cl gob.cu gob.do gob.ec gob.es gob.gt gob.hn gob.mx gob.ni gob.pa gob.pe gob.pk gob.sv gob.ve gog.pk goiania.br gok.pk gol.no gop.pk gorizia.it gorlice.pl gos.pk gouv.ci gouv.fr gouv.ht gouv.km gouv.ml gouv.sn gov.ac gov.ae gov.af gov.al gov.ao gov.ar gov.as gov.au gov.az gov.ba gov.bb gov.bd gov.bf gov.bh gov.bm gov.bn gov.br gov.bs gov.bt gov.bw gov.by gov.bz gov.cd gov.cl gov.cm gov.cn gov.co gov.cx gov.cy gov.cz gov.dm gov.do gov.dz gov.ec gov.ee gov.eg gov.et gov.fj gov.gd gov.ge gov.gh gov.gi gov.gn gov.gr gov.gu gov.gy gov.hk gov.ie gov.il gov.in gov.io gov.iq gov.ir gov.it gov.jo gov.kg gov.kh gov.ki gov.km gov.kn gov.kp gov.kw gov.kz gov.la gov.lb gov.lc gov.lk gov.lr gov.ls gov.lt gov.lv gov.ly gov.ma gov.me gov.mg gov.mk gov.ml gov.mn gov.mo gov.mr gov.ms gov.mu gov.mv gov.mw gov.my gov.mz gov.na gov.ng gov.nr gov.om gov.ph gov.pk gov.pl gov.pn gov.pr gov.ps gov.pt gov.pw gov.py gov.qa gov.rs gov.rw gov.sa gov.sb gov.sc gov.sd gov.sg gov.sh gov.sl gov.so gov.ss gov.sx gov.sy gov.tj gov.tl gov.tm gov.tn gov.to gov.tr gov.tt gov.tw gov.ua gov.ug gov.uk gov.vc gov.ve gov.vn gov.ws gov.ye gov.za gov.zm gov.zw govt.nz gr.it gr.jp grajewo.pl gran.no grane.no granvin.no gratangen.no greta.fr grimstad.no grondar.za grong.no grosseto.it grp.lk gru.br grue.no gs.cn gsm.pl gu.us guam.gu gub.uy gujarat.in gulen.no gunma.jp guovdageaidnu.no gv.ao gv.at gwangju.kr gx.cn gye.ec gyeongbuk.kr gyeonggi.kr gyeongnam.kr gz.cn h.bg h.se ha.cn ha.no habmer.no hadsel.no hagebostad.no hagiang.vn haiduong.vn haiphong.vn halden.no halsa.no hamar.no hamaroy.no hammarfeasta.no hammerfest.no hanam.vn hanoi.vn hapmir.no haram.no hareid.no harstad.no hasvik.no hatinh.vn hattfjelldal.no haugesund.no haugiang.vn hb.cn he.cn health.nz health.vn hemne.no hemnes.no hemsedal.no herad.no hi.cn hi.us hiroshima.jp hitra.no hjartdal.no hjelmeland.no hk.cn hl.cn hl.no hm.no hn.cn hoabinh.vn hobol.no hof.no hokkaido.jp hokksund.no hol.no hole.no holmestrand.no holtalen.no honefoss.no hornindal.no horten.no hotel.hu hotel.lk hotel.tz hoyanger.no hoylandet.no hs.kr hue.vn huissier-justice.fr hungyen.vn hurdal.no hurum.no hvaler.no hyllestad.no hyogo.jp i.bg i.ng i.ph i.se ia.bo ia.br ia.us ia.ve ibaraki.jp ibestad.no ibr.ec id.au id.bd id.cv id.fj id.ir id.lv id.ly id.us id.vn idf.il idrett.no idv.hk idv.tw if.ua iglesias-carbonia.it iglesiascarbonia.it il.us ilawa.pl im.it imb.br imperia.it in.ni in.rs in.th in.ua in.us incheon.kr ind.br ind.gt ind.in ind.kw ind.tn inderoy.no indigena.bo industria.bo inf.br inf.cu inf.mk info.az info.bb info.bd info.bj info.bo info.ec info.eg info.et info.fj info.gu info.ht info.hu info.in info.ke info.ki info.la info.ls info.ml info.mv info.nf info.ni info.nr info.pl info.pr info.ro info.sd info.tn info.tr info.tt info.tz info.ve info.vn info.zm ing.pa ingatlan.hu inst.ml int.ar int.az int.bo int.ci int.cv int.in int.la int.lk int.mv int.mw int.ni int.pt int.tj int.ve int.vn internet.in intl.tn io.in io.kr io.vn is.it isa.us isernia.it ishikawa.jp isla.pr it.ao it.bd it.kr its.me ivano-frankivsk.ua iveland.no ivgu.no iwate.jp iwi.nz iz.hr j.bg jab.br jampa.br jan-mayen.no jaworzno.pl jdf.br jeju.kr jelenia-gora.pl jeonbuk.kr jeonnam.kr jessheim.no jevnaker.no jgora.pl jl.cn jogasz.hu joinville.br jolster.no jondal.no jor.br jorpeland.no js.cn jus.br jx.cn k.bg k.se k12.ec k12.il k12.tr k12.vi kafjord.no kagawa.jp kagoshima.jp kalisz.pl kanagawa.jp karasjohka.no karasjok.no karlsoy.no karmoy.no karpacz.pl kartuzy.pl kaszuby.pl katowice.pl kautokeino.no kazimierz-dolny.pl kep.tr kepno.pl ketrzyn.pl kg.kr kh.ua khanhhoa.vn kharkiv.ua kharkov.ua kherson.ua khmelnitskiy.ua khmelnytskyi.ua kiengiang.vn kiev.ua kirkenes.no kirovograd.ua kiwi.nz klabu.no klepp.no klodzko.pl km.ua kobierzyce.pl kochi.jp kolobrzeg.pl komforb.se kommunalforbund.se kommune.no komvux.se kongsberg.no kongsvinger.no konin.pl konskowola.pl kontum.vn konyvelo.hu kop.id kopervik.no kr.it kr.ua kraanghke.no kragero.no kristiansand.no kristiansund.no krodsherad.no krokstadelva.no kropyvnytskyi.ua krym.ua ks.ua ks.us kumamoto.jp kutno.pl kv.ua kvafjord.no kvalsund.no kvam.no kvanangen.no kvinesdal.no kvinnherad.no kviteseid.no kvitsoy.no ky.us kyiv.ua kyoto.jp l.bg l.se la-spezia.it la.us laakesvuemie.no lahppi.no laichau.vn lakas.hu lamdong.vn lanbib.se langevag.no langson.vn laocai.vn lapy.pl laquila.it lardal.no larvik.no laspezia.it lat.ec latina.it lavagis.no lavangen.no law.za laz.it lazio.it lc.it le.it leangaviika.no lebesby.no lebork.pl lecce.it lecco.it leg.br legnica.pl leikanger.no leilao.br leirfjord.no leirvik.no leka.no leksvik.no lel.br lenvik.no lerdal.no lesja.no levanger.no lezajsk.pl lg.jp lg.ua li.it lib.ee lier.no lierne.no lig.it liguria.it lillehammer.no lillesand.no limanowa.pl lindas.no lindesnes.no livorno.it llc.ge ln.cn lo.it loabat.no lodi.it lodingen.no log.br loisirs.bj loj.ec lom.it lom.no lombardia.it lombardy.it lomza.pl londrina.br longan.vn loppa.no lorenskog.no loten.no lowicz.pl lt.it lt.ua ltd.cy ltd.gi ltd.lk ltd.uk lu.it lubin.pl lucania.it lucca.it lugansk.ua luhansk.ua lukow.pl lund.no lunner.no luroy.no luster.no lutsk.ua lv.ua lviv.ua lyngdal.no lyngen.no m.bg m.se ma.us macapa.br maceio.br macerata.it mail.pl malatvuopmi.no malbork.pl malopolska.pl malselv.no malvik.no manaus.br mandal.no mantova.it maori.nz mar.it marche.it maringa.br marker.no marnardal.no masfjorden.no masoy.no massa-carrara.it massacarrara.it mat.br matera.it matta-varjjat.no mazowsze.pl mazury.pl mb.ca mb.it mc.it md.us me.eg me.in me.it me.ke me.kr me.so me.ss me.tz me.uk me.us med.br med.ec med.ee med.ht med.ly med.om med.pa med.sa med.sd medecin.km media.hu media.pl medicina.bo medio-campidano.it mediocampidano.it meland.no meldal.no melhus.no meloy.no meraker.no messina.it mi.it mi.th mi.us miasta.pl midsund.no midtre-gauldal.no mie.jp mielec.pl mielno.pl mil.ac mil.ae mil.al mil.ar mil.az mil.ba mil.bd mil.bo mil.br mil.by mil.cl mil.cn mil.co mil.cy mil.do mil.ec mil.eg mil.fj mil.gh mil.gt mil.hn mil.id mil.in mil.io mil.iq mil.jo mil.kg mil.km mil.kr mil.kz mil.lv mil.mg mil.mv mil.my mil.mz mil.ng mil.ni mil.no mil.nz mil.pe mil.ph mil.pl mil.py mil.qa mil.rw mil.sh mil.st mil.sy mil.tj mil.tm mil.to mil.tr mil.tt mil.tw mil.tz mil.ug mil.uy mil.vc mil.ve mil.ye mil.za mil.zm mil.zw milan.it milano.it mincom.tn miyagi.jp miyazaki.jp mjondalen.no mk.ua mktg.ec mn.it mn.us mo-i-rana.no mo.cn mo.it mo.us moareke.no mobi.gp mobi.ke mobi.ng mobi.tz mod.gi modalen.no modena.it modum.no mol.it molde.no molise.it mon.ec money.bj monza-brianza.it monza-e-della-brianza.it monza.it monzabrianza.it monzaebrianza.it monzaedellabrianza.it morena.br mosjoen.no moskenes.no moss.no movimiento.bo mp.br mr.no mragowo.pl ms.it ms.kr ms.us mt.it mt.us muni.il muosat.no mus.br museum.mv museum.no museum.om musica.ar musica.bo mutual.ar my.id mykolaiv.ua n.bg n.se na.it naamesjevuemie.no nagano.jp nagasaki.jp naklo.pl namdalseid.no namdinh.vn name.az name.eg name.et name.fj name.hr name.mk name.mv name.my name.ng name.pr name.qa name.tj name.tr name.tt name.vn namsos.no namsskogan.no nannestad.no naples.it napoli.it nara.jp naroy.no narviika.no narvik.no nat.cu nat.tn natal.br natural.bo naturbruksgymn.se naustdal.no navuotna.no nb.ca nc.tr nc.us nd.us ne.jp ne.ke ne.kr ne.tz ne.ug ne.us nedre-eiker.no nesna.no nesodden.no nesoddtangen.no nesseby.no nesset.no net.ac net.ae net.af net.ag net.ai net.al net.am net.ar net.au net.az net.ba net.bb net.bd net.bh net.bj net.bm net.bn net.bo net.br net.bs net.bt net.bw net.bz net.ci net.cm net.cn net.co net.cu net.cv net.cw net.cy net.dm net.do net.dz net.ec net.eg net.et net.fj net.fm net.ge net.gg net.gh net.gl net.gn net.gp net.gr net.gt net.gu net.gy net.hk net.hn net.ht net.id net.il net.im net.in net.io net.iq net.ir net.je net.jo net.kg net.kh net.ki net.kn net.kw net.ky net.kz net.la net.lb net.lc net.lk net.lr net.ls net.lv net.ly net.ma net.me net.mk net.ml net.mo net.ms net.mt net.mu net.mv net.mw net.mx net.my net.mz net.na net.nf net.ng net.ni net.nr net.nz net.om net.pa net.pe net.ph net.pk net.pl net.pn net.pr net.ps net.pt net.py net.qa net.rw net.sa net.sb net.sc net.sd net.sg net.sh net.sl net.so net.ss net.st net.sy net.th net.tj net.tm net.tn net.to net.tr net.tt net.tw net.ua net.uk net.uy net.uz net.vc net.ve net.vi net.vn net.vu net.ws net.ye net.za net.zm news.hu nf.ca nghean.vn ngo.lk ngo.ph ngo.za nh.us nhs.uk nic.in nic.tj nic.za nieruchomosci.pl niigata.jp nikolaev.ua ninhbinh.vn ninhthuan.vn nis.za nissedal.no niteroi.br nittedal.no nj.us nl.ca nl.no nm.cn nm.us no.it nom.ag nom.co nom.es nom.fr nom.io nom.km nom.mg nom.nc nom.ni nom.pa nom.pe nom.pl nom.ro nom.tm nom.ve nom.za nombre.bo nome.cv nome.pt nord-aurdal.no nord-fron.no nord-odal.no norddal.no nordkapp.no nordre-land.no nordreisa.no nore-og-uvdal.no not.br notaires.km noticias.bo notodden.no notteroy.no novara.it nowaruda.pl ns.ca nsn.us nsw.au nt.au nt.ca nt.no nt.ro ntr.br ntr.ec nu.ca nu.it nuoro.it nv.us nx.cn ny.us nysa.pl o.bg o.se od.ua odda.no odesa.ua odessa.ua odo.br odont.ec of.by of.no off.ai og.ao og.it ogliastra.it oh.us oita.jp ok.us okayama.jp okinawa.jp oksnes.no ol.no olawa.pl olbia-tempio.it olbiatempio.it olecko.pl olkusz.pl olsztyn.pl omasvuotna.no on.ca on.vn ong.br online.ge opoczno.pl opole.pl oppdal.no oppegard.no or.at or.bi or.ci or.cr or.id or.it or.jp or.ke or.kr or.mu or.th or.tz or.ug or.us org.ac org.ae org.af org.ag org.ai org.al org.am org.ao org.ar org.au org.az org.ba org.bb org.bd org.bh org.bi org.bj org.bm org.bn org.bo org.br org.bs org.bt org.bw org.bz org.ci org.cn org.co org.cu org.cv org.cw org.cy org.dm org.do org.dz org.ec org.ee org.eg org.es org.et org.fj org.fm org.ge org.gg org.gh org.gi org.gl org.gn org.gp org.gr org.gt org.gu org.gy org.hk org.hn org.ht org.hu org.il org.im org.in org.io org.iq org.ir org.je org.jo org.kg org.kh org.ki org.km org.kn org.kp org.kw org.ky org.kz org.la org.lb org.lc org.lk org.lr org.ls org.lv org.ly org.ma org.me org.mg org.mk org.ml org.mn org.mo org.ms org.mt org.mu org.mv org.mw org.mx org.my org.mz org.na org.ng org.ni org.nr org.nz org.om org.pa org.pe org.pf org.ph org.pk org.pl org.pn org.pr org.ps org.pt org.py org.qa org.ro org.rs org.rw org.sa org.sb org.sc org.sd org.se org.sg org.sh org.sk org.sl org.sn org.so org.ss org.st org.sv org.sy org.sz org.tj org.tm org.tn org.to org.tr org.tt org.tw org.ua org.ug org.uk org.uy org.uz org.vc org.ve org.vi org.vn org.vu org.ws org.ye org.za org.zm org.zw oristano.it orkanger.no orkdal.no orland.no orskog.no orsta.no osaka.jp osasco.br osen.no oslo.no osoyro.no osteroy.no ostre-toten.no ostroda.pl ostroleka.pl ostrowiec.pl ostrowwlkp.pl ot.it ote.bj other.nf overhalla.no ovre-eiker.no oyer.no oygarden.no oystre-slidre.no oz.au p.bg p.se pa.it pa.us padova.it padua.it palermo.it palmas.br parliament.nz parma.it parti.se patria.bo pavia.it pb.ao pc.it pc.pl pd.it pe.ca pe.it pe.kr per.jo per.la per.nf perso.ht perso.tn perugia.it pesaro-urbino.it pesarourbino.it pescara.it pg.in pg.it pharmaciens.km phd.jo phutho.vn phuyen.vn pi.it piacenza.it piedmont.it piemonte.it pila.pl pisa.it pistoia.it pisz.pl pl.ua plc.ly plc.uk plo.ps plurinacional.bo pmn.it pn.it po.it poa.br podhale.pl podlasie.pl pol.dz pol.ht pol.tr police.uk politica.bo polkowice.pl poltava.ua pomorskie.pl pomorze.pl ponpes.id pordenone.it porsanger.no porsangu.no porsgrunn.no post.in potenza.it powiat.pl pp.az pp.se ppg.br pr.it pr.ml pr.us prato.it prd.fr prd.km prd.mg press.cy press.ma press.se presse.km presse.ml pri.ee principe.st priv.hu priv.me priv.no priv.pl pro.az pro.br pro.cy pro.ec pro.fj pro.ht pro.in pro.mv pro.om pro.pr pro.tt pro.vn prochowice.pl prof.ec prof.pr profesional.bo pruszkow.pl przeworsk.pl psc.br psi.br psic.ec psiq.ec pt.it pu.it pub.ec pub.sa publ.cv publ.pt pueblo.bo pug.it puglia.it pulawy.pl pv.it pvh.br pvt.ge pz.it q.bg qc.ca qh.cn qld.au qsl.br quangbinh.vn quangnam.vn quangngai.vn quangninh.vn quangtri.vn r.bg r.se ra.it rade.no radio.br radom.pl radoy.no ragusa.it rahkkeravju.no raholt.no raisa.no rakkestad.no ralingen.no rana.no randaberg.no rar.ve rauma.no ravenna.it rawa-maz.pl rc.it re.it re.kr re.no realestate.pl rec.br rec.nf rec.ro rec.ve recife.br red.sv reggio-calabria.it reggio-emilia.it reggiocalabria.it reggioemilia.it reklam.hu rel.ht rel.pl rendalen.no rennebu.no rennesoy.no rep.br rep.kp res.in restaurant.bj resto.bj revista.bo rg.it ri.it ri.us ribeirao.br rieti.it riik.ee rimini.it rindal.no ringebu.no ringerike.no ringsaker.no rio.br rio.ec riobranco.br riopreto.br risor.no rissa.no rivne.ua rl.no rm.it rn.it ro.it roan.no rodoy.no rollag.no roma.it rome.it romsa.no romskog.no roros.no rost.no rovigo.it rovno.ua royken.no royrvik.no rrpp.ec ruovat.no rv.ua rybnik.pl rygge.no rzeszow.pl s.bg s.se sa.au sa.cr sa.it saga.jp saitama.jp sal.ec salangen.no salat.no salerno.it saltdal.no salud.bo salvador.br samnanger.no sampa.br sandefjord.no sandnes.no sandnessjoen.no sandoy.no sanok.pl santamaria.br santoandre.br saobernardo.br saogonca.br saotome.st sar.it sardegna.it sardinia.it sarpsborg.no sassari.it sauda.no sauherad.no savona.it sb.ua sc.cn sc.ke sc.kr sc.ls sc.tz sc.ug sc.us sch.ae sch.bd sch.id sch.ir sch.jo sch.lk sch.ly sch.ng sch.qa sch.sa sch.ss sch.zm school.ge school.in school.nz school.za sci.eg sd.cn sd.us sebastopol.ua sec.ps seg.ar seg.br sejny.pl sel.no selbu.no selje.no seljord.no senasa.ar seoul.kr sevastopol.ua sex.hu sex.pl sf.no sh.cn shiga.jp shimane.jp shizuoka.jp shop.ht shop.hu shop.pl si.it sic.it sicilia.it sicily.it siellak.no siena.it sigdal.no siljan.no siracusa.it sirdal.no sjc.br sk.ca skanit.no skanland.no skaun.no skedsmo.no skedsmokorset.no ski.no skien.no skierva.no skiptvet.no skjak.no skjervoy.no sklep.pl skoczow.pl skodje.no slask.pl slattum.no sld.do sld.pa slg.br slupsk.pl slz.br sm.ua smola.no sn.cn snaase.no snasa.no snillfjord.no snoasa.no so.it soc.dz soc.lk social.br soctrang.vn sogndal.no sogne.no sokndal.no sola.no solund.no somna.no sondre-land.no sondrio.it songdalen.no sonla.vn sor-aurdal.no sor-fron.no sor-odal.no sor-varanger.no sorfold.no sorocaba.br sorreisa.no sortland.no sorum.no sos.pl sosnowiec.pl sp.it spjelkavik.no sport.eg sport.hu spydeberg.no sr.it srv.br ss.it st.no stalowa-wola.pl stange.no starachowice.pl stargard.pl stat.no stathelle.no stavanger.no stavern.no steigen.no steinkjer.no stjordal.no stjordalshalsen.no stokke.no stor-elvdal.no stord.no stordal.no store.bb store.nf store.ro store.st store.ve storfjord.no strand.no stranda.no stryn.no su.it sud-sardegna.it sudsardegna.it suedtirol.it sula.no suldal.no suli.hu sumy.ua sund.no sunndal.no suohkan.no surnadal.no suwalki.pl sv.it svalbard.no sveio.no svelvik.no swidnica.pl swiebodzin.pl swinoujscie.pl sx.cn sykkylven.no szczecin.pl szczytno.pl szex.hu szkola.pl t.bg t.se ta.it taa.it tana.no tananger.no taranto.it targi.pl tarnobrzeg.pl tas.au taxi.br tayninh.vn tc.br te.it te.ua tec.br tec.ve tech.ec tecnologia.bo tel.tr tempio-olbia.it tempioolbia.it teo.br teramo.it terni.it ternopil.ua test.tj tgory.pl thaibinh.vn thainguyen.vn thanhhoa.vn thanhphohochiminh.vn the.br thuathienhue.vn tiengiang.vn time.no tingvoll.no tinn.no tj.cn tjeldsund.no tjielte.no tjome.no tksat.bo tm.cy tm.dz tm.fr tm.hu tm.km tm.mc tm.no tm.pl tm.ro tm.se tm.za tmp.br tn.it tn.us tnx.ge to.it tochigi.jp tokke.no tokushima.jp tokyo.jp tolga.no tonsberg.no torino.it torsken.no tos.it toscana.it tottori.jp tourism.bj tourism.pl tourism.tn toyama.jp tozsde.hu tp.it tr.it tr.no tra.kp trana.no tranby.no trani-andria-barletta.it trani-barletta-andria.it traniandriabarletta.it tranibarlettaandria.it tranoy.no transporte.bo trapani.it travel.in travel.pl travinh.vn trd.br trentin-sud-tirol.it trentin-sudtirol.it trentin-sued-tirol.it trentin-suedtirol.it trentino-a-adige.it trentino-aadige.it trentino-alto-adige.it trentino-altoadige.it trentino-s-tirol.it trentino-stirol.it trentino-sud-tirol.it trentino-sudtirol.it trentino-sued-tirol.it trentino-suedtirol.it trentino.it trentinoa-adige.it trentinoaadige.it trentinoalto-adige.it trentinoaltoadige.it trentinos-tirol.it trentinostirol.it trentinosud-tirol.it trentinosued-tirol.it trentinosuedtirol.it trentinsud-tirol.it trentinsudtirol.it trentinsued-tirol.it trentinsuedtirol.it trento.it treviso.it trieste.it troandin.no trogstad.no tromsa.no tromso.no trondheim.no trysil.no ts.it tsk.tr tt.im tul.ec tur.ar tur.br tur.ec turek.pl turin.it turystyka.pl tuscany.it tuyenquang.vn tv.bb tv.bd tv.bo tv.br tv.eg tv.im tv.in tv.it tv.jo tv.sd tv.tr tv.tz tvedestrand.no tw.cn tx.us tychy.pl tydal.no tynset.no tysfjord.no tysnes.no tysvar.no u.bg u.se ub.in ud.it udi.br udine.it uenorge.no uio.ec uk.in ullensaker.no ullensvang.no ulsan.kr ulstein.no ulvik.no umb.it umbria.it univ.bj univ.sn unjarga.no up.in urbino-pesaro.it urbinopesaro.it us.in us.ug ustka.pl ut.us utazas.hu utsira.no uz.ua uzhgorod.ua uzhhorod.ua v.bg va.it va.no va.us vaapste.no vadso.no vaga.no vagan.no vagsoy.no vaksdal.no val-d-aosta.it val-daosta.it vald-aosta.it valle-aosta.it valle-d-aosta.it valle-daosta.it valle.no valleaosta.it valled-aosta.it valledaosta.it vallee-aoste.it vallee-d-aoste.it valleeaoste.it valleedaoste.it vang.no vanylven.no vao.it vardo.no varese.it varggat.no varoy.no vb.it vc.it vda.it ve.it vefsn.no vega.no vegarshei.no ven.it veneto.it venezia.it venice.it vennesla.no verbania.it verbano-cusio-ossola.it vercelli.it verdal.no verona.it verran.no vestby.no vestnes.no vestre-slidre.no vestre-toten.no vestvagoy.no vet.br vet.ec veterinaire.km vevelstad.no vf.no vgs.no vi.it vi.us vibo-valentia.it vibovalentia.it vic.au vicenza.it video.hu vik.no vikna.no vindafjord.no vinhlong.vn vinhphuc.vn vinnica.ua vinnytsia.ua viterbo.it vix.br vlog.br vn.ua voagat.no volda.no volyn.ua voss.no vossevangen.no vr.it vs.it vt.it vt.us vv.it w.bg w.se wa.au wa.us wakayama.jp walbrzych.pl warmia.pl warszawa.pl waw.pl web.bo web.do web.gu web.id web.lk web.nf web.ni web.pk web.tj web.tr web.ve web.za wegrow.pl wi.us wielun.pl wiki.bo wiki.br wlocl.pl wloclawek.pl wodzislaw.pl wolomin.pl wroclaw.pl wv.us www.ro wy.us x.bg x.se xj.cn xxx.ec xyz.br xz.cn y.bg y.se yalta.ua yamagata.jp yamaguchi.jp yamanashi.jp yenbai.vn yk.ca yn.cn z.bg z.se zachpomor.pl zagan.pl zakarpattia.ua zaporizhzhe.ua zaporizhzhia.ua zarow.pl zgora.pl zgorzelec.pl zhitomir.ua zhytomyr.ua zj.cn zlg.br zp.ua zt.ua';
  var SUFFIX2 = null;

  // The registered domain a handle belongs to: alice.example.com -> example.com, alice.example.co.uk -> example.co.uk.
  function regDomain(h) {
    if (!SUFFIX2) { SUFFIX2 = {}; SUFFIX2_LIST.split(' ').forEach(function (s) { SUFFIX2[s] = true; }); }
    var l = String(h || '').split('.');
    return l.slice(l.length > 2 && SUFFIX2[l.slice(-2).join('.')] ? -3 : -2).join('.');
  }

  // Turn what people paste ("@Alice.Example.com", "https://alice.example.com/") into a handle.
  function normalizeInput(raw) {
    var s = String(raw || '').trim();
    s = s.replace(/^@/, '').replace(/^[a-z]+:\/\//i, '').replace(/[\/?#].*$/, '').replace(/\.$/, '');
    s = s.toLowerCase();
    var notes = [];
    if (/[^\x00-\x7f]/.test(s)) {
      try {
        var puny = new URL('http://' + s).hostname;
        if (puny && puny !== s) { notes.push('Non-ASCII domain: handles use the punycode form, ' + puny + '.'); s = puny; }
      } catch (e) { /* leave as is; validation will explain */ }
    }
    return { handle: s, notes: notes };
  }

  // Same checks and order as ensureValidHandle, plus the registration-time TLD block list.
  function validateHandle(h) {
    var bad = /[^a-zA-Z0-9.-]/.exec(h);
    if (bad) {
      if (bad[0] === '_') return 'Underscores (_) are not allowed in Bluesky handles (unlike X/Twitter). Use a hyphen instead, like my-name.bsky.social.';
      if (/\s/.test(bad[0])) return 'Spaces are not allowed in a handle. Use a hyphen instead, like my-name.bsky.social.';
      return 'Only ASCII letters, digits, dashes and dots are allowed in a handle ("' + bad[0] + '" is not).';
    }
    if (h.length > 253) return 'Too long (253 characters max).';
    var labels = h.split('.');
    if (labels.length < 2) return 'A handle needs at least two parts, like example.com.';
    for (var i = 0; i < labels.length; i++) {
      var l = labels[i];
      if (l.length < 1) return 'Empty part (two dots in a row, or a dot at the start).';
      if (l.length > 63) return 'One part is longer than 63 characters.';
      if (l[0] === '-' || l[l.length - 1] === '-') return 'Parts can not start or end with a hyphen ("' + l + '").';
      if (i + 1 === labels.length && !/^[a-zA-Z]/.test(l)) return 'The last part (TLD) must start with a letter.';
    }
    for (var j = 0; j < DISALLOWED_TLDS.length; j++) {
      if (h.endsWith(DISALLOWED_TLDS[j])) return DISALLOWED_TLDS[j] + ' domains can not be used as Bluesky handles.';
    }
    return null;
  }

  // Extra rule Bluesky's own PDS applies when a *.bsky.social name is created or changed
  // (packages/pds/src/handle/index.ts ensureHandleServiceConstraints): the part before
  // .bsky.social has no dots and is 3-18 characters. A note, not an error: it doesn't
  // decide whether an existing handle resolves, so the live checks still run.
  var SERVICE_DOMAIN = '.bsky.social';
  function serviceNameNote(h) {
    if (!h || !h.endsWith(SERVICE_DOMAIN) || h === SERVICE_DOMAIN.slice(1)) return null;
    var front = h.slice(0, -SERVICE_DOMAIN.length), why = null, fix = null;
    if (front.indexOf('.') !== -1) { why = 'it has a dot in it ("' + front + '")'; fix = 'Use a hyphen instead of the dot'; }
    else if (front.length < 3) { why = '"' + front + '" is only ' + front.length + ' character' + (front.length === 1 ? '' : 's'); fix = 'Pick a longer name'; }
    else if (front.length > 18) { why = '"' + front + '" is ' + front.length + ' characters'; fix = 'Shorten it'; }
    if (!why) return null;
    return 'If you are trying to pick this as a new handle: Bluesky\'s server only accepts 3 to 18 characters before .bsky.social, ' +
      'with no dots, and ' + why + '. That alone gives "Invalid Handle" at sign-up or when changing handles. ' +
      fix + ', or use your own domain (no length limit).';
  }

  // DoH JSON "data" for TXT. Cloudflare: "\"did=...\"" (quoted chunks, maybe several: "a" "b").
  // Google: unquoted. Returns the record as the resolver sees it (chunks joined).
  function parseTxtData(data) {
    data = String(data);
    if (data[0] !== '"') return data;
    var out = '', i = 0, inQ = false;
    while (i < data.length) {
      var c = data[i];
      if (!inQ) { if (c === '"') inQ = true; i++; continue; }
      if (c === '"') { inQ = false; i++; continue; }
      if (c === '\\' && i + 1 < data.length) {
        var m = /^\d{3}/.exec(data.slice(i + 1));
        if (m) { out += String.fromCharCode(parseInt(m[0], 10)); i += 4; continue; }
        out += data[i + 1]; i += 2; continue;
      }
      out += c; i++;
    }
    return out;
  }

  // Exactly what HandleResolver.parseDnsResult does, plus reasons when it gives no answer.
  function pickDid(records) {
    var found = records.filter(function (r) { return r.indexOf('did=') === 0; });
    var notes = [];
    if (found.length === 1) {
      var did = found[0].slice(4);
      if (!isValidDid(did)) {
        notes.push('The record is "' + found[0] + '", but "' + did + '" is not a valid DID' +
          (did !== did.trim() ? ' (it has spaces around it; remove them).' :
            /^did:/.test(did) ? '.' : ' (it should look like did:plc:abc123...).'));
      }
      return { did: did, valid: isValidDid(did), notes: notes };
    }
    if (found.length > 1) {
      var same = found.every(function (r) { return r === found[0]; });
      notes.push('There are ' + found.length + ' "did=" records. Bluesky treats that as ambiguous and ignores ALL of them' +
        (same ? ' (even though they are identical).' : '.') + ' Delete all but one.');
      var all = [];
      found.forEach(function (r) { var d = r.slice(4); if (all.indexOf(d) < 0) all.push(d); });
      return { did: null, valid: false, notes: notes, all: all };
    }
    records.forEach(function (r) {
      var t = r.trim();
      if (t.indexOf('did=') === 0) notes.push('"' + r + '" has spaces before "did=". Remove them.');
      else if (/^did\s*=/i.test(t)) notes.push('"' + r + '": the prefix must be exactly lower-case "did=" with no spaces.');
      else if (/^did:/.test(t)) notes.push('"' + r + '" is missing the "did=" prefix. The value must be did=' + t + '.');
      else if (t.indexOf('did=') > 0) notes.push('"' + r + '" must START with "did=". Remove what comes before it.');
    });
    return { did: null, valid: false, notes: notes };
  }

  // What the resolver does with the body of /.well-known/atproto-did.
  function parseWellKnown(text) {
    var first = String(text).split('\n')[0].trim();
    if (first.indexOf('did:') === 0) return { did: first, note: isValidDid(first) ? null : '"' + first + '" is not a valid DID.' };
    var note = /^\s*</.test(text) ? 'The URL returns an HTML page, not a DID. Many site builders send every unknown path to the home page.' :
      first ? 'The first line is "' + first.slice(0, 80) + '", which does not start with "did:".' : 'The file is empty.';
    return { did: null, note: note };
  }

  // Does the DID document claim this handle? (The second half of the two-way check.)
  function akaHandles(doc) {
    return ((doc && doc.alsoKnownAs) || []).filter(function (a) { return /^at:\/\//.test(a); })
      .map(function (a) { return a.slice(5).toLowerCase(); });
  }
  function pdsOf(doc) {
    var s = ((doc && doc.service) || []).filter(function (x) { return /#atproto_pds$/.test(x.id) || x.type === 'AtprotoPersonalDataServer'; })[0];
    return s ? s.serviceEndpoint : null;
  }

  function didDocUrl(did) {
    if (/^did:plc:/.test(did)) return 'https://plc.directory/' + did;
    if (/^did:web:/.test(did)) return 'https://' + decodeURIComponent(did.slice(8)) + '/.well-known/did.json';
    return null;
  }

  // ---- network (fetchFn injectable for tests) ----
  function getJson(fetchFn, url, headers) {
    return fetchFn(url, { headers: headers || {} }).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, json: j }; });
    });
  }

  function dnsName(s) { return String(s || '').replace(/\.$/, '').toLowerCase(); }

  // Shown under every "All good": a wave of Invalid Handle posts followed a Bluesky core-service migration on 2026-11-12
  // (status.bsky.app, 00:50-01:35 UTC); every handle I checked hours later was fine again.
  var STATUS_NOTE = 'Lots of people seeing it at the same time? Then it is likely on Bluesky\'s side. Bluesky posts outages and ' +
    'maintenance at https://status.bsky.app; the waves I have looked at cleared within a day.';

  // Nameservers of domain parking / marketplace services, and GoDaddy's "expired, pending deletion" servers.
  // A domain served by these is not pointing at anyone's own DNS any more. Kept short on purpose: only names checked
  // to exist, and only services whose whole job is parked or for-sale domains.
  var PARKING = {
    'pendingrenewaldeletion.com': 'GoDaddy (expired domain)', 'sedoparking.com': 'Sedo', 'parkingcrew.net': 'ParkingCrew',
    'above.com': 'Above.com', 'dan.com': 'Dan.com', 'afternic.com': 'Afternic', 'hugedomains.com': 'HugeDomains',
    'parity.domains': 'Parity'
  };
  function parkingOf(ns) {
    for (var i = 0; i < ns.length; i++) {
      for (var k in PARKING) if (ns[i] === k || ns[i].slice(-(k.length + 1)) === '.' + k) return PARKING[k];
    }
    return null;
  }

  // type: 'TXT' (default) or 'NS'. Also reports a CNAME sitting on `name` itself (a name with a CNAME can't
  // have a TXT record of its own; resolvers follow the alias instead).
  function doh(fetchFn, name, type) {
    var q = 'name=' + encodeURIComponent(name) + '&type=' + (type || 'TXT');
    function shape(res) {
      var j = res.json || {}, ans = j.Answer || [];
      var txt = ans.filter(function (a) { return a.type === 16; }).map(function (a) { return parseTxtData(a.data); });
      var ns = ans.filter(function (a) { return a.type === 2; }).map(function (a) { return dnsName(a.data); });
      var c = ans.filter(function (a) { return a.type === 5 && dnsName(a.name) === dnsName(name); })[0];
      return { rcode: j.Status, txt: txt, ns: ns, cname: c ? dnsName(c.data) : null };
    }
    return getJson(fetchFn, 'https://cloudflare-dns.com/dns-query?' + q, { accept: 'application/dns-json' }).then(shape)
      .catch(function () { return getJson(fetchFn, 'https://dns.google/resolve?' + q).then(shape); })
      .catch(function () { return { rcode: null, txt: [], error: 'DNS lookup failed (both Cloudflare and Google DNS-over-HTTPS).' }; });
  }

  function wellKnown(fetchFn, h) {
    return fetchFn('https://' + h + '/.well-known/atproto-did', {}).then(function (r) {
      return r.text().then(function (t) {
        var p = parseWellKnown(t);
        // A 404 is simply "no file here" (normal with the TXT method), whatever error page the site sends with it.
        if (r.status === 404 && !p.did) p.note = 'HTTP 404: there is no file at this address. That is fine if you use the TXT ' +
          'record; it only matters for the file method.';
        else if (r.status !== 200) p.note = 'HTTP ' + r.status + '. ' + (p.did ? '' : p.note);
        return { reached: true, status: r.status, did: p.did, note: p.note };
      });
    }, function () {
      return { reached: false, did: null, note: 'Your browser could not read it. Usually the site just does not allow ' +
        'cross-site reads (normal, and Bluesky does not care), or the domain has no website.' };
    });
  }

  var API = 'https://public.api.bsky.app/xrpc/';

  // Handles like alice.bsky.social are handed out by a hosting service (PDS). Its describeServer lists the domains it
  // gives out ("availableUserDomains", e.g. ".bsky.social"); the service answers for those names, not the user's DNS.
  function userDomains(fetchFn, base) {
    return getJson(fetchFn, String(base).replace(/\/+$/, '') + '/xrpc/com.atproto.server.describeServer').then(function (r) {
      var d = r.status === 200 && r.json && r.json.availableUserDomains;
      return Array.isArray(d) ? d : null;
    }, function () { return null; });
  }
  function hostedSuffix(h, domains) {
    var s = (domains || []).map(function (d) {
      d = String(d).toLowerCase();
      return d.charAt(0) === '.' ? d : '.' + d;
    }).filter(function (d) { return d.length > 1 && h.length > d.length && h.slice(-d.length) === d; });
    return s[0] || null;
  }
  // Has the Bluesky relay ever crawled this hostname as a PDS? 404 HostNotFound = no. Sends ACAO *.
  var RELAY = 'https://relay1.us-east.bsky.network/xrpc/';
  function hostKnown(fetchFn, host) {
    return getJson(fetchFn, RELAY + 'com.atproto.sync.getHostStatus?hostname=' + encodeURIComponent(host)).then(function (r) {
      return r.status === 200 && r.json && dnsName(r.json.hostname) === dnsName(host) ? r.json : null;
    }, function () { return null; });
  }
  function hostName(url) { return String(url || '').replace(/^https?:\/\//, '').replace(/[\/:].*$/, ''); }

  function check(rawInput, rawExpected, fetchFn) {
    fetchFn = fetchFn || root.fetch.bind(root);
    var n = normalizeInput(rawInput);
    var h = n.handle;
    var rep = { handle: h, inputNotes: n.notes, syntaxError: validateHandle(h) };
    if (!h) { rep.syntaxError = 'Type a handle, like alice.example.com.'; }
    var svc = serviceNameNote(h);
    if (!rep.syntaxError && svc) rep.inputNotes = rep.inputNotes.concat([svc]);
    if (rep.syntaxError) { rep.verdict = verdict(rep); return Promise.resolve(rep); }

    // Common mistake: full name typed into a panel that appends the zone -> _atproto.<h>.<zone>.
    var labels = h.split('.');
    var reg = regDomain(h);
    var zones = [h];
    if (reg !== h) zones.push(reg);

    var expectedP = Promise.resolve(null);
    var ex = normalizeInput(rawExpected).handle;
    if (ex) {
      expectedP = /^did:/.test(ex) ? Promise.resolve({ did: String(rawExpected).trim(), from: 'did' }) :
        getJson(fetchFn, API + 'com.atproto.identity.resolveHandle?handle=' + encodeURIComponent(ex))
          .then(function (r) { return { did: r.json.did || null, from: ex }; }, function () { return { did: null, from: ex }; });
    }

    return Promise.all([
      doh(fetchFn, '_atproto.' + h),
      wellKnown(fetchFn, h),
      getJson(fetchFn, API + 'com.atproto.identity.resolveHandle?handle=' + encodeURIComponent(h))
        .then(function (r) { return { did: r.json.did || null, message: r.json.message || null }; },
          function () { return { did: null, message: 'Request failed.' }; }),
      expectedP
    ]).then(function (res) {
      rep.dns = res[0]; rep.dns.pick = pickDid(rep.dns.txt);
      rep.http = res[1]; rep.appview = res[2]; rep.expected = res[3];
      // DNS first, then HTTP: same order as the official resolver.
      rep.did = rep.dns.pick.did || rep.http.did || null;
      rep.didSource = rep.dns.pick.did ? 'dns' : rep.http.did ? 'http' : null;
      if (!rep.did && rep.appview.did) { rep.did = rep.appview.did; rep.didSource = 'appview'; }
      var extra = [];
      if (!rep.dns.pick.did) {
        extra = zones.map(function (z) {
          var name = '_atproto.' + h + '.' + z;
          return doh(fetchFn, name).then(function (d) { return { name: name, zone: z, d: d }; });
        });
        extra.push(doh(fetchFn, h).then(function (d) { return { name: h, zone: null, d: d }; }));
        // Does the domain exist at all? NXDOMAIN on the registered name (RFC 8020: nothing below it exists either)
        // almost always means it expired. regDomain() knows co.uk-style suffixes; a suffix it does not know
        // makes it ask about the suffix itself, which exists, so the worst case is a missed hint, never a false one.
        // Asking for NS also shows where the domain is hosted: parking / for-sale nameservers mean it lapsed or was sold.
        var apex = reg;
        extra.push(doh(fetchFn, apex, 'NS').then(function (d) {
          rep.apex = { name: apex, rcode: d.rcode, ns: d.ns || [], parked: parkingOf(d.ns || []) };
          return { name: apex, zone: null, d: { txt: [] } };
        }));
        // Nothing resolves and the parent is a hosting service that hands out <name>.<parent>: there is no DNS for the
        // user to fix; the account was renamed, moved, deleted, or the service is down.
        if (!rep.did && reg !== h) {
          var parent = labels.slice(1).join('.');
          extra.push(userDomains(fetchFn, 'https://' + parent).then(function (d) {
            var sfx = hostedSuffix(h, d);
            rep.parentHost = sfx ? { name: parent, suffix: sfx } : null;
            if (d) return null;
            // No answer at all. If the Bluesky relay knows the parent as a PDS, the hosting service itself is down.
            // (The relay's own "status" field is not used: it says "offline" for many PDSes that answer fine.)
            return hostKnown(fetchFn, parent).then(function (k) {
              if (k) rep.parentHost = { name: parent, suffix: '.' + parent, down: true, accounts: k.accountCount };
            });
          }).then(function () { return { name: parent, zone: null, d: { txt: [] } }; }));
        }
        // _atproto.<h> is an alias. If a made-up name next to it is the same alias, it comes from a wildcard (*) record.
        if (rep.dns.cname) {
          extra.push(doh(fetchFn, 'wildcard-probe-q7x.' + h).then(function (d) {
            rep.dns.wildcard = !!d.cname && d.cname === rep.dns.cname;
            return { name: 'wildcard-probe-q7x.' + h, zone: null, d: { txt: [] } };
          }));
        }
      }
      // Several different did= records: find out whose each one is. Typical case: an organisation with a second
      // account (e.g. a sports or language desk) added that account's record at the main name.
      var dupesP = Promise.resolve(null);
      var all = (rep.dns.pick.all || []).filter(isValidDid);
      var malformed = (rep.dns.pick.all || []).length - all.length;
      // One good record next to a mistyped one: still look the good one up, to say whether to keep it.
      if (all.length > 1 || (all.length === 1 && malformed > 0)) {
        dupesP = Promise.all(all.map(function (did) {
          var url = didDocUrl(did);
          return Promise.all([
            url ? getJson(fetchFn, url).then(function (r) { return r.status === 200 ? r.json : null; }, function () { return null; }) : null,
            getJson(fetchFn, API + 'app.bsky.actor.getProfile?actor=' + encodeURIComponent(did))
              .then(function (r) { return r.json && r.json.handle ? r.json : null; }, function () { return null; })
          ]).then(function (x) {
            var o = { did: did, aka: x[0] ? akaHandles(x[0]) : null, displayName: x[1] ? (x[1].displayName || '') : '' };
            // A sibling account under this domain: does it already have its own record where it belongs?
            var sh = o.aka && o.aka[0];
            if (!sh || sh === h || sh.slice(-(h.length + 1)) !== '.' + h) return o;
            return doh(fetchFn, '_atproto.' + sh).then(function (d) {
              o.ownRecord = !d.cname && (d.txt || []).some(function (t) { return t.trim() === 'did=' + did; });
              return o;
            });
          });
        }));
      }
      return Promise.all([Promise.all(extra), dupesP]).then(function (x) { rep.dupes = x[1]; return x[0]; });
    }).then(function (misplaced) {
      rep.misplaced = misplaced.filter(function (m) {
        // A CNAME on the name means its TXT answers belong to the alias target (often a wildcard * pointing at the
        // domain itself), not to a record someone typed there. A name with a CNAME can't hold its own TXT.
        if (m.d.cname) return false;
        return m.d.txt.some(function (t) { return /did[=:]/i.test(t); });
      }).map(function (m) { return { name: m.name, zone: m.zone, txt: m.d.txt.filter(function (t) { return /did[=:]/i.test(t); }) }; });
      if (!rep.did || !isValidDid(rep.did)) return null;
      var url = didDocUrl(rep.did);
      return Promise.all([
        url ? getJson(fetchFn, url).then(function (r) { return r.status === 200 ? r.json : null; }, function () { return null; }) : null,
        // Keep the error name too: "AccountTakedown" / "AccountDeactivated" explain an invalid handle better than DNS can.
        getJson(fetchFn, API + 'app.bsky.actor.getProfile?actor=' + encodeURIComponent(rep.did))
          .then(function (r) { return r.json && r.json.handle ? r.json : { error: (r.json && r.json.error) || null }; },
            function () { return null; })
      ]);
    }).then(function (docs) {
      if (docs) {
        rep.doc = docs[0]; rep.aka = akaHandles(docs[0]); rep.pds = pdsOf(docs[0]);
        rep.profile = docs[1] && docs[1].handle ? { handle: docs[1].handle, displayName: docs[1].displayName || '' } : null;
        rep.profileError = docs[1] && docs[1].error ? String(docs[1].error) : null;
      }
      if (!rep.pds || !/^https:\/\//.test(rep.pds)) return null;
      return userDomains(fetchFn, rep.pds).then(function (d) {
        var sfx = hostedSuffix(h, d);
        rep.hosted = sfx ? { pds: hostName(rep.pds), suffix: sfx } : null;
      });
    }).then(function () {
      rep.verdict = verdict(rep);
      return rep;
    });
  }

  // Host/name to type in a DNS panel whose zone is `zone`: "_atproto" for the apex, "_atproto.alice" for alice.<zone>.
  function hostField(h, zone) {
    var full = '_atproto.' + h;
    return full.slice(0, full.length - zone.length - 1);
  }

  // Which of several did= records to keep, and where the others belong.
  // Number of positions where two equal-length strings differ (Infinity if lengths differ).
  function charDiff(a, b) {
    if (a.length !== b.length) return Infinity;
    var n = 0;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) n++;
    return n;
  }

  function dupeSteps(r) {
    var d = r.dupes || [];
    var out = [];
    var good = (r.dns && r.dns.pick && r.dns.pick.all || []).filter(isValidDid);
    (r.dns && r.dns.pick && r.dns.pick.all || []).forEach(function (x) {
      if (isValidDid(x)) return;
      var near = good.filter(function (g) { return charDiff(g, x) <= 2; });
      out.push('Delete did=' + x + ': that is not a valid DID, so it can never match an account' +
        (near.length === 1 ? ' (it looks like a mistyped copy of did=' + near[0] + ').' : '.'));
    });
    if (d.length === 1) {
      var one = d[0];
      if (one.aka && one.aka.indexOf(r.handle) >= 0) {
        out.push('Keep did=' + one.did + ': that account' + (one.displayName ? ' ("' + one.displayName + '")' : '') +
          ' claims ' + r.handle + ' as its handle. Once it is the only did= record, re-verify the handle in the app.');
      } else {
        out.push('The other record, did=' + one.did + ', ' + (one.aka ? 'claims ' + (one.aka.join(', ') || 'no handle') +
          ', not ' + r.handle + '. Make sure it is the DID of the account that should have this handle.' :
          'could not be looked up. Make sure it is the DID of the account that should have this handle.'));
      }
      return out;
    }
    if (d.length < 2) return out;
    var keep = d.filter(function (x) { return x.aka && x.aka.indexOf(r.handle) >= 0; });
    var who = function (x) { return x.did + (x.displayName ? ' ("' + x.displayName + '")' : ''); };
    if (keep.length !== 1) {
      return out.concat(d.map(function (x) {
        return 'did=' + who(x) + ': ' + (x.aka ? 'claims ' + (x.aka.join(', ') || 'no handle') + '.' : 'could not load its DID document.');
      }), ['None of them (or more than one) claims ' + r.handle + ', so the record list alone can not say which to keep. ' +
        'Keep the DID of the account that should have this handle.']);
    }
    out.push('Keep did=' + keep[0].did + ': that account' + (keep[0].displayName ? ' ("' + keep[0].displayName + '")' : '') +
      ' is the one that claims ' + r.handle + ' as its handle.');
    d.forEach(function (x) {
      if (x === keep[0]) return;
      var h = x.aka && x.aka[0];
      var s = 'Remove did=' + x.did + ' from _atproto.' + r.handle + ': it is a different account' +
        (x.displayName ? ' ("' + x.displayName + '")' : '') + (h ? ', which uses ' + h : '') + '.';
      if (h && h !== r.handle && h.slice(-(r.handle.length + 1)) === '.' + r.handle) {
        var zone = regDomain(r.handle);
        s += x.ownRecord ? ' It already has its own record at _atproto.' + h + ', so this one is a leftover and can simply go.' :
          ' Its own record goes at _atproto.' + h + ' (host/name "' + hostField(h, zone) + '" in the DNS panel for ' + zone +
          '), not here.';
      }
      out.push(s);
    });
    return out;
  }

  // Handle is a name UNDER a lapsed domain: the user may only have been given that name (shared/free subdomain service,
  // a friend's or a community's domain). Then renewing is not theirs to do. Real case 2026-11-19: *.sysky.club went NXDOMAIN.
  function notYoursStep(r) {
    if (r.handle === r.apex.name) return [];
    return ['If ' + r.apex.name + ' is not your own domain (a friend, a community, or a shared handle service gave you this name), ' +
      'only its owner can renew it, so ask them. Until then you can pick another handle in the app (Settings, Account, Handle; ' +
      'for most people a free .bsky.social name, see the FAQ below); ' +
      'your posts and followers stay, they belong to your account (DID), not the name. You can usually still log in with your email (see the FAQ below).'];
  }

  // Website hosts that give each user a subdomain SITE (files) but no DNS. A TXT record is impossible there and "ask the
  // domain's owner" is wrong advice; the /.well-known/atproto-did file is the way. Real case: armettebriard.neocities.org
  // (2026-11-21) works through the file only. Kept to hosts where a user controls the site's files.
  var SITE_HOSTS = { 'github.io': 'GitHub Pages', 'gitlab.io': 'GitLab Pages', 'neocities.org': 'Neocities',
    'netlify.app': 'Netlify', 'pages.dev': 'Cloudflare Pages', 'vercel.app': 'Vercel' };
  function siteHost(h) {
    var z = regDomain(h);
    return h !== z && SITE_HOSTS[z] ? { zone: z, name: SITE_HOSTS[z] } : null;
  }
  function siteFileSteps(r, sh) {
    var out = [r.handle + ' is a ' + sh.name + ' address. ' + sh.name + ' runs the DNS for ' + sh.zone + ', so you can not add a ' +
      'TXT record there (and nobody can add one for you). Use the file method instead: in the app, Settings, Account, Handle, ' +
      '"I have my own domain", then the "No DNS Panel" tab. It shows the address and your DID.',
      'In your site, create a folder named .well-known at the top level, and in it a plain-text file named atproto-did (no file ' +
      'extension) that contains only your DID (it starts with "did:"). It must open at https://' + r.handle + '/.well-known/atproto-did. ' +
      'Then press verify in the app.'];
    // Checked 2026-11-21 on ichtally.github.io: the default (Jekyll) build left a .well-known folder out (404); with an empty
    // .nojekyll file at the root it was served. 2026-11-21 (s49): 3 of 3 working github.io handles checked (ccanonne, kawarimidoll,
    // juliusgarbe) use include: [".well-known"] in _config.yml instead (two of them as the only line). .nojekyll would switch off
    // a Jekyll theme, so the config line comes first.
    if (sh.zone === 'github.io') out.push('GitHub Pages: the default build (Jekyll) leaves out folders whose name starts with a dot, ' +
      'so .well-known is missing from the live site (404). Fix: add the line include: [".well-known"] to _config.yml at the top of ' +
      'the repository (create that file if there is none). That works with or without a Jekyll theme. A plain-HTML site can use an ' +
      'empty file named .nojekyll at the top instead, but not a Jekyll-themed site: .nojekyll switches the build off.');
    // No TXT option on these hosts, so the generic 404 note ("fine if you use the TXT record") would mislead here.
    if (r.http.reached) out.push('Right now /.well-known/atproto-did: ' + (r.http.status === 404 && !r.http.did ?
      'HTTP 404, the file is not there (yet).' : r.http.note));
    return out;
  }

  // level: ok | wait | bad. steps: what to do next.
  function verdict(r) {
    if (r.syntaxError) return { level: 'bad', title: 'Not a valid handle', steps: [r.syntaxError] };
    var steps = [];
    if (r.dns.error) steps.push(r.dns.error);
    if (!r.did) {
      if (r.apex && r.apex.rcode === 3) {
        return { level: 'bad', title: 'The domain ' + r.apex.name + ' does not exist right now',
          steps: steps.concat(['DNS answers "no such domain" (NXDOMAIN) for ' + r.apex.name + ', so there is nothing for Bluesky to check. ' +
            'Check the spelling first. If it is right, the registration has most likely expired: check it at your registrar ' +
            '(or with a WHOIS lookup) and renew it.',
          'After renewing, it can take a few hours for the domain to come back. If the _atproto TXT record is gone, add it again: ' +
            'host/name "' + hostField(r.handle, r.apex.name) + '", value "did=" followed by your DID. Then re-verify the handle in the app.'],
            notYoursStep(r)) };
      }
      // SERVFAIL on the registered name: it is registered, but its nameservers do not answer (or DNSSEC is broken), so no
      // record under it can be read. Real case 2026-11-22: mattckrause.com, renewed 11-16, both nameservers silent
      // (Google + Cloudflare: "No Reachable Authority"); without this branch the checker said "add a TXT record".
      if (r.apex && r.apex.rcode === 2) {
        return { level: 'bad', title: 'The DNS servers for ' + r.apex.name + ' are not answering',
          steps: steps.concat(['DNS lookups for ' + r.apex.name + ' fail (SERVFAIL): the domain is registered, but the nameservers it ' +
            'points to do not answer, so Bluesky can not read any record there, including _atproto. This is a problem with the ' +
            'domain\'s DNS hosting, not with Bluesky or your account.',
          'At the place you bought the domain (registrar), check which nameservers it uses and that the DNS service behind them is ' +
            'still active, especially if you recently renewed, transferred or changed the domain. A DNSSEC setting left on at the ' +
            'registrar after moving DNS to another provider fails the same way: switch DNSSEC off there, or set it up at the new provider.',
          'If it worked until recently and you changed nothing, it can be a short outage at the DNS provider: check again in an hour. ' +
            'Once the domain answers again, make sure the TXT record is still there: host/name "' + hostField(r.handle, r.apex.name) +
            '", value "did=" followed by your DID. Then re-verify the handle in the app.'], notYoursStep(r)) };
      }
      if (r.apex && r.apex.parked) {
        return { level: 'bad', title: 'The domain ' + r.apex.name + ' looks parked, for sale, or expired',
          steps: steps.concat(['Its nameservers are ' + r.apex.ns.join(', ') + ', which belong to ' + r.apex.parked +
            ', a domain parking / marketplace service. That usually means the registration lapsed and the domain was ' +
            'parked or sold, so your DNS records (including _atproto) are no longer being served.',
          'Check at your registrar (or with a WHOIS lookup) whether you still own ' + r.apex.name + '. If you do, renew it if needed, ' +
            'set its nameservers back to your DNS provider, and re-add the TXT record: host/name "' + hostField(r.handle, r.apex.name) +
            '", value "did=" followed by your DID. Then re-verify the handle in the app.',
          'If someone else owns it now, the handle can not come back; pick a new one in the app (your posts and followers stay, they ' +
            'belong to your DID, not the handle).'], notYoursStep(r)) };
      }
      if (r.parentHost && !r.dns.pick.notes.length && !(r.misplaced || []).length) {
        var ph = r.parentHost;
        if (ph.down) {
          return { level: 'bad', title: 'The hosting service ' + ph.name + ' is not answering',
            steps: steps.concat([ph.name + ' is a Bluesky hosting service (PDS): the Bluesky network has seen ' +
              (ph.accounts ? ph.accounts + ' accounts' : 'accounts') + ' there. Handles ending in .' + ph.name +
              ' are answered by that service, and right now it does not respond (checked ' +
              'https://' + ph.name + '/xrpc/com.atproto.server.describeServer). So there is no DNS record for you to add.',
            'If your account lives on ' + ph.name + ', the handle shows as invalid because the service is down or unreachable. ' +
              'Usually that is temporary: wait, then check again, or ask whoever runs ' + ph.name + '.',
            'If it is gone for good, your account (posts, follows) lives on that server too. Moving it elsewhere needs a backup or ' +
              'the account\'s recovery (rotation) key; without either, the realistic option is a new account.']) };
        }
        return { level: 'bad', title: 'No account uses ' + r.handle + ' on ' + ph.name + ' right now',
          steps: steps.concat([ph.name + ' is a hosting service: it hands out names ending in ' + ph.suffix + ' itself, and it ' +
            'answers for them. So there is no DNS record for you to add here.',
          'Most likely the account changed its handle, moved to another host, or was deleted. Check the spelling. If it is your ' +
            'account, your posts and followers belong to your DID, not the name: log in and pick a handle again in Settings, ' +
            'Account, Handle. If the service itself seems down, try again later or contact ' + ph.name + '.']) };
      }
      steps = steps.concat(r.dns.pick.notes);
      steps = steps.concat(dupeSteps(r));
      (r.misplaced || []).forEach(function (m) {
        if (m.name === r.handle) steps.push((r.dns.pick.all || []).length ?
          'There is also a did= record on ' + m.name + ' itself. Bluesky never looks there, so it does nothing; you can delete it.' :
          'Found a DID record on ' + m.name + ' itself. It must be on _atproto.' + r.handle +
          ' (in most DNS panels: host/name "_atproto", type TXT).');
        else steps.push('Found the record at ' + m.name + ': the full name was typed into a DNS panel that adds "' + m.zone +
          '" by itself. Set the host/name field to just "' + hostField(r.handle, m.zone) + '".');
      });
      var zone2 = regDomain(r.handle);
      if (!(r.misplaced || []).length && !r.dns.pick.notes.length && r.dns.cname) {
        steps.push('_atproto.' + r.handle + ' is an alias (CNAME) for ' + r.dns.cname + ', which has no did= record. ' +
          (r.dns.wildcard ? 'It comes from a wildcard (*) record on the domain, often added by the registrar for parking or URL ' +
            'forwarding, so you may never have added it yourself.' : 'A name with a CNAME can not have a TXT record of its own.'));
        steps.push(r.dns.wildcard ?
          'Add the TXT record anyway: an exact record at _atproto.' + r.handle + ' takes priority over the wildcard. Type TXT, host/name "' +
            hostField(r.handle, zone2) + '", value "did=" followed by your DID.' :
          'Delete the CNAME on _atproto.' + r.handle + ', then add a TXT record there: host/name "' + hostField(r.handle, zone2) +
            '", value "did=" followed by your DID.');
        if (zone2 !== r.handle) steps.push('If ' + zone2 + ' is not your own domain (a shared or free subdomain ' +
          'service), only its owner can change this; ask them.');
      } else if (!(r.misplaced || []).length && !r.dns.pick.notes.length && !r.dns.txt.length && siteHost(r.handle)) {
        steps = steps.concat(siteFileSteps(r, siteHost(r.handle)));
      } else if (!(r.misplaced || []).length && !r.dns.pick.notes.length) {
        steps.push(r.dns.txt.length ?'There are TXT records on _atproto.' + r.handle + ', but none starts with "did=".' :
          'No TXT record found at _atproto.' + r.handle + '. Add one: type TXT, host/name "' +
          hostField(r.handle, zone2) + '"' +
          (zone2 !== r.handle ? ' (if the domain in your DNS panel is ' + zone2 + ')' : '') +
          ', value "did=" followed by your DID. DNS changes can take a few minutes to an hour to show up.');
        // Real case 2026-11-21: a community domain (live, own DNS) no longer had the member's _atproto record ("kicked out").
        if (!r.dns.txt.length && zone2 !== r.handle) steps.push('If ' + zone2 + ' is not your own domain (a friend, ' +
          'a community, or a shared handle service gave you this name), you can not add this record yourself: its owner manages it, and ' +
          'it may have been removed. Ask them, or pick another handle in the app (Settings, Account, Handle; for most people a free ' +
          '.bsky.social name, see the FAQ below); your posts and followers ' +
          'stay, they belong to your account (DID), not the name. You can usually still log in with your email (see the FAQ below).');
        if (r.http.reached) steps.push('/.well-known/atproto-did: ' + r.http.note);
      }
      return { level: 'bad', title: 'Bluesky can not find an account for ' + r.handle, steps: steps };
    }
    if (!isValidDid(r.did)) return { level: 'bad', title: 'The record is there but the DID in it is broken', steps: steps.concat(r.dns.pick.notes) };
    if (r.dns.pick.did && r.http.did && r.dns.pick.did !== r.http.did) {
      steps.push('DNS says ' + r.dns.pick.did + ' but /.well-known/atproto-did says ' + r.http.did + '. DNS wins; fix or remove the other one.');
    }
    if (r.expected && r.expected.did && r.expected.did !== r.did) {
      return { level: 'bad', title: r.handle + ' points to a different account than ' + r.expected.from,
        steps: steps.concat(['The record points to ' + r.did + ', but ' + r.expected.from + ' is ' + r.expected.did +
          '. Replace the value with did=' + r.expected.did + '.']) };
    }
    if (r.didSource === 'appview') steps.push('No DNS record found; Bluesky\'s servers resolve it another way (most likely ' +
      'https://' + r.handle + '/.well-known/atproto-did, which your browser could not read).');
    if (r.appview.did && r.appview.did !== r.did) steps.push('Bluesky\'s public API still returns ' + r.appview.did +
      ' for this name (cached or not yet updated). Give it some time.');
    var claimed = (r.aka || []).indexOf(r.handle) >= 0;
    if (!r.doc) {
      return { level: 'wait', title: r.handle + ' points to ' + r.did, steps: steps.concat(['Could not load the DID document to finish the check.']) };
    }
    if (!claimed) {
      var half = ['The account currently claims: ' + ((r.aka || []).join(', ') || 'no handle') + '.',
        'Finish in the Bluesky app: change your handle, choose the option for your own domain, enter ' + r.handle + ' and verify.'];
      // Real case 2026-11-13: a PDS could not verify an itch.io subdomain handle because the site answered the PDS's server
      // request with a Cloudflare bot challenge. A browser gets the file fine, so this page can not see that block.
      if (r.didSource === 'http') half.push('Your browser could read https://' + r.handle + '/.well-known/atproto-did, but when you ' +
        'verify, it is your account\'s server' + (r.pds ? ' (' + hostName(r.pds) + ')' : '') + ' that fetches it, not your browser. ' +
        'If the app says it can not verify, the website may be blocking server requests (for example a Cloudflare bot check). ' +
        'Ask whoever runs the site to let /.well-known/atproto-did through' + (siteHost(r.handle) ? '.' :
        ', or, if you control the domain\'s DNS, add a TXT record ' +
        'instead: host/name "' + hostField(r.handle, regDomain(r.handle)) + '", value did=' + r.did + '.'));
      return { level: 'wait', title: 'Half done: the domain points to the account, but the account has not switched to it',
        steps: steps.concat(half) };
    }
    // The records are fine, but the account they point to is suspended or switched off. Typical symptom: an OLDER account that
    // used to have this handle shows "Invalid Handle", because the domain now points to this one.
    if (r.profileError === 'AccountTakedown' || r.profileError === 'AccountDeactivated') {
      var down = r.profileError === 'AccountTakedown';
      var older = 'If an older account used to have ' + r.handle + ', that one now shows "Invalid Handle", because the domain points ' +
        'away from it. Either point the record back to the older account\'s DID (then re-verify the handle there), or give the ' +
        'older account a different handle.';
      var out = [r.handle + ' points to ' + r.did + ' and that account claims it back, so the handle setup itself is fine.',
        down ? 'But Bluesky\'s public API answers "AccountTakedown" for this account: it has been suspended, so it does not show ' +
          'up in the app. DNS changes can not fix that; if it is your account and you think it is a mistake, contact Bluesky ' +
          'support or moderation.' :
          'But Bluesky\'s public API answers "AccountDeactivated": the owner switched the account off. Logging in to it again ' +
          'reactivates it.',
        older];
      if (/(^|\.)brid\.gy$/.test(hostName(r.pds))) out.push('This account is bridged from the fediverse by Bridgy Fed (it lives on ' +
        hostName(r.pds) + '). If the fediverse account moved or its address changed, Bridgy Fed can create a NEW Bluesky account ' +
        'that takes over the same handle, and the older bridged account (with the followers) loses it. The fediverse server\'s ' +
        'admin or Bridgy Fed (https://fed.brid.gy/docs) can sort that out.');
      return { level: 'bad', title: down ? 'The records are right, but Bluesky has suspended the account they point to' :
        'The records are right, but the account they point to is deactivated', steps: steps.concat(out) };
    }
    if (r.profile && r.profile.handle === r.handle && r.hosted) {
      var sub = r.handle.slice(0, -r.hosted.suffix.length);
      steps.push('This handle comes from your hosting service, which hands out names ending in ' + r.hosted.suffix +
        ' (your account lives on ' + r.hosted.pds + '). The service answers for it, so there is nothing for you to set up in DNS.');
      steps.push('Still seeing "Invalid Handle" in the app? Then it works right now; the service was probably slow or down during ' +
        'an earlier re-check. To force a fresh check: Settings, Account, Handle, type ' + sub + ' as the new handle (the ' +
        r.hosted.suffix + ' part is added for you), then Save. If it keeps happening, tell your hosting service.');
      steps.push(STATUS_NOTE);
      return { level: 'ok', title: 'All good: ' + r.handle + ' is a working Bluesky handle', steps: steps };
    }
    if (r.profile && r.profile.handle === r.handle) {
      if (r.didSource === 'http') steps.push('This handle works through the .well-known file only. That is allowed, but if the ' +
        'website is down or slow when Bluesky re-checks, the handle shows as invalid until the next check. ' +
        (siteHost(r.handle) ? 'On ' + siteHost(r.handle).name + ' the file is the only option (no DNS access), so keep it in place ' +
          'when you rebuild or redesign the site.' :
          'A DNS TXT record (_atproto, value did=' + r.did + ') does not depend on the website.'));
      steps.push('Still seeing "Invalid Handle" in the app? Then the setup is fine right now and an earlier check failed. ' +
        'To force a fresh check: Settings, Account, Handle, "I have my own domain", enter ' + r.handle + ', verify, then "Update to ' +
        r.handle + '".');
      steps.push(STATUS_NOTE);
      return { level: 'ok', title: 'All good: ' + r.handle + ' is a working Bluesky handle', steps: steps };
    }
    var shown = r.profile ? r.profile.handle : '(profile not found)';
    return { level: 'wait', title: 'Your records are right; Bluesky shows "' + shown + '" for now',
      steps: steps.concat([shown === 'handle.invalid' ?
        'Both directions check out now, so Bluesky\'s cached result is stale. It re-checks on its own; saving the handle again in the app usually forces it.' :
        'Both directions check out. Bluesky\'s view updates shortly after a handle change.']) };
  }

  var api = { normalizeInput: normalizeInput, validateHandle: validateHandle, serviceNameNote: serviceNameNote, parseTxtData: parseTxtData, pickDid: pickDid,
    parseWellKnown: parseWellKnown, hostField: hostField, regDomain: regDomain, akaHandles: akaHandles, pdsOf: pdsOf, didDocUrl: didDocUrl, isValidDid: isValidDid,
    hostedSuffix: hostedSuffix, siteHost: siteHost, check: check, verdict: verdict };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.HandleCheck = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
