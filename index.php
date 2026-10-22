<?php
/* =============================================================
   DETECTIVE : plateforme d'investigation OSINT (fichier unique)
   -------------------------------------------------------------
   Installation complète : voir README.md
     1. Importer schema.sql une seule fois dans la BDD
     2. Copier config.sample.php → config.php et renseigner les accès
   Ce fichier assure à la fois l'API (JSON) et l'interface (le graphe).
   ============================================================= */

/* Configuration BDD : config.php (non versionné, voir .gitignore) prend le
   dessus s'il existe ; sinon on retombe sur des variables d'environnement
   (utile pour un déploiement hors XAMPP). Jamais de identifiants en dur ici. */
$cfgFile = __DIR__.'/config.php';
$cfg = is_file($cfgFile) ? (require $cfgFile) : [];
$DB_HOST = $cfg['db_host'] ?? (getenv('DETECTIVE_DB_HOST') ?: '127.0.0.1');
$DB_NAME = $cfg['db_name'] ?? (getenv('DETECTIVE_DB_NAME') ?: 'detective');
$DB_USER = $cfg['db_user'] ?? (getenv('DETECTIVE_DB_USER') ?: 'detective_app');
$DB_PASS = $cfg['db_pass'] ?? (getenv('DETECTIVE_DB_PASS') ?: '');

/* ---------- connexion PDO (préparée = pas d'injection SQL) ---------- */
function db() {
  global $DB_HOST,$DB_NAME,$DB_USER,$DB_PASS;
  static $pdo=null;
  if($pdo) return $pdo;
  try {
    $pdo=new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4",$DB_USER,$DB_PASS,[
      PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES=>false,
    ]);
  } catch(PDOException $e){ http_response_code(500); die(json_encode(['error'=>'BDD: '.$e->getMessage()])); }
  return $pdo;
}

/* =============================================================
   API : déclenchée par ?api=...
   ============================================================= */
if(isset($_GET['api'])){
  header('Content-Type: application/json; charset=utf-8');
  header('X-Content-Type-Options: nosniff');
  $body=json_decode(file_get_contents('php://input'),true) ?: [];
  $id=isset($_GET['id'])?(int)$_GET['id']:0;
  $out=function($d,$c=200){ http_response_code($c); echo json_encode($d,JSON_UNESCAPED_UNICODE); exit; };
  $imp=fn($v)=>in_array($v??'',['critique','eleve','normal','faible','lacune','exclu'],true)?$v:'normal';
  $cf =fn($v)=>in_array($v??'',['h','m','l'],true)?$v:'m';
  $stt=fn($v)=>in_array($v??'',['a_verifier','en_cours','confirme','vuln','rien','ecarte'],true)?$v:'a_verifier';

  /* liste ordonnée des 11 champs communs d'un nœud, sanitizés (réutilisée par add_node / edit_node / import) */
  $sanitizeNode=function($b) use ($imp,$cf,$stt){
    return [
      substr((string)($b['type']??'autre'),0,40),
      substr(trim((string)($b['label']??'')),0,120),
      substr((string)($b['value']??''),0,500) ?: null,
      $imp($b['importance']??null), $stt($b['statut']??null), $cf($b['confidence']??null),
      substr((string)($b['source']??''),0,500) ?: null,
      substr((string)($b['image']??''),0,500) ?: null,
      substr((string)($b['file_url']??''),0,500) ?: null,
      substr((string)($b['file_name']??''),0,255) ?: null,
      substr((string)($b['note']??''),0,5000) ?: null,
    ];
  };
  /* prépare le dossier uploads/ (créé au besoin, exécution PHP bloquée dedans), réutilisée par upload / upload_doc */
  $prepUploadDir=function(){
    $dir=__DIR__.'/uploads';
    if(!is_dir($dir)) @mkdir($dir,0755,true);
    // l'.htaccess doit exister même si le dossier préexistait déjà (ex: dépôt cloné avec uploads/ vide)
    $ht="$dir/.htaccess";
    if(!is_file($ht)){
      @file_put_contents($ht,"php_flag engine off\nRemoveHandler .php .phtml .php3 .php4 .php5 .pht\nRemoveType .php .phtml .php3 .php4 .php5 .pht\n");
    }
    return $dir;
  };

  try {
    switch($_GET['api']){

      case 'graph':
        $pid=isset($_GET['project'])?(int)$_GET['project']:1;
        $q=db()->prepare("SELECT * FROM nodes WHERE project_id=? ORDER BY id"); $q->execute([$pid]); $nodes=$q->fetchAll();
        $q=db()->prepare("SELECT * FROM links WHERE project_id=? ORDER BY id"); $q->execute([$pid]); $links=$q->fetchAll();
        $deg=[];
        foreach($links as $l){ $deg[$l['source']]=($deg[$l['source']]??0)+1; $deg[$l['target']]=($deg[$l['target']]??0)+1; }
        foreach($nodes as &$n){ $n['id']=(int)$n['id']; $n['degree']=$deg[$n['id']]??0;
          $n['x']=$n['x']!==null?(float)$n['x']:null; $n['y']=$n['y']!==null?(float)$n['y']:null; }
        foreach($links as &$l){ $l['id']=(int)$l['id']; $l['source']=(int)$l['source']; $l['target']=(int)$l['target']; }
        $out(['nodes'=>$nodes,'links'=>$links]);

      /* --- liste des projets / missions --- */
      case 'projects':
        $rows=db()->query("SELECT p.id, p.name, p.target,
             (SELECT COUNT(*) FROM nodes n WHERE n.project_id=p.id) AS nodes
           FROM projects p ORDER BY p.id")->fetchAll();
        foreach($rows as &$r){ $r['id']=(int)$r['id']; $r['nodes']=(int)$r['nodes']; }
        $out($rows);

      /* --- créer un projet --- */
      case 'add_project':
        $name=trim($body['name']??''); if($name==='') $out(['error'=>'nom requis'],422);
        db()->prepare("INSERT INTO projects (name,target,note) VALUES (?,?,?)")
            ->execute([substr($name,0,160), substr($body['target']??'',0,255) ?: null, substr($body['note']??'',0,5000) ?: null]);
        $out(['id'=>(int)db()->lastInsertId()],201);

      /* --- supprimer un projet (et tout son contenu) --- */
      case 'del_project':
        if(!$id) $out(['error'=>'id requis'],400);
        if($id===1) $out(['error'=>'le projet initial ne peut être supprimé'],422);
        db()->prepare("DELETE FROM links WHERE project_id=?")->execute([$id]);
        db()->prepare("DELETE FROM nodes WHERE project_id=?")->execute([$id]);
        db()->prepare("DELETE FROM projects WHERE id=?")->execute([$id]);
        $out(['ok'=>true]);

      case 'add_node':
        $label=trim($body['label']??''); if($label==='') $out(['error'=>'label requis'],422);
        $pid=(int)($body['project_id']??1) ?: 1;
        $st=db()->prepare("INSERT INTO nodes (project_id,type,label,value,importance,statut,confidence,source,image,file_url,file_name,note)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
        $st->execute(array_merge([$pid],$sanitizeNode($body)));
        $out(['id'=>(int)db()->lastInsertId()],201);

      case 'edit_node':
        if(!$id) $out(['error'=>'id requis'],400);
        $label=trim($body['label']??''); if($label==='') $out(['error'=>'label requis'],422);
        $st=db()->prepare("UPDATE nodes SET type=?,label=?,value=?,importance=?,statut=?,confidence=?,source=?,image=?,file_url=?,file_name=?,note=? WHERE id=?");
        $st->execute(array_merge($sanitizeNode($body),[$id]));
        $out(['ok'=>true]);

      case 'move':
        if(!$id) $out(['error'=>'id requis'],400);
        db()->prepare("UPDATE nodes SET x=?,y=? WHERE id=?")->execute([(float)($body['x']??0),(float)($body['y']??0),$id]);
        $out(['ok'=>true]);

      case 'del_node':
        if(!$id) $out(['error'=>'id requis'],400);
        db()->prepare("DELETE FROM links WHERE source=? OR target=?")->execute([$id,$id]);
        db()->prepare("DELETE FROM nodes WHERE id=?")->execute([$id]);
        $out(['ok'=>true]);

      case 'add_link':
        $s=(int)($body['source']??0); $t=(int)($body['target']??0);
        if(!$s||!$t||$s===$t) $out(['error'=>'source/target invalides'],422);
        // les deux nœuds doivent exister et appartenir au même projet
        $q=db()->prepare("SELECT id,project_id FROM nodes WHERE id IN (?,?)"); $q->execute([$s,$t]);
        $rows=$q->fetchAll();
        if(count($rows)!==2) $out(['error'=>'nœud introuvable'],422);
        if((int)$rows[0]['project_id']!==(int)$rows[1]['project_id']) $out(['error'=>'liens inter-projets interdits'],422);
        $pid=(int)$rows[0]['project_id'];
        db()->prepare("INSERT INTO links (project_id,source,target,label,confidence) VALUES (?,?,?,?,?)")
            ->execute([$pid,$s,$t,substr($body['label']??'',0,120) ?: null,$cf($body['confidence']??null)]);
        $out(['id'=>(int)db()->lastInsertId()],201);

      case 'del_link':
        if(!$id) $out(['error'=>'id requis'],400);
        db()->prepare("DELETE FROM links WHERE id=?")->execute([$id]);
        $out(['ok'=>true]);

      /* --- upload d'image (validé : vraie image, ext limitée, nom aléatoire) --- */
      case 'upload':
        if(empty($_FILES['file'])||$_FILES['file']['error']!==UPLOAD_ERR_OK) $out(['error'=>'aucun fichier reçu'],400);
        $f=$_FILES['file'];
        if($f['size']>5*1024*1024) $out(['error'=>'fichier trop grand (max 5 Mo)'],422);
        $info=@getimagesize($f['tmp_name']);
        if($info===false) $out(['error'=>'fichier non reconnu comme image'],422);
        $ext=['image/jpeg'=>'jpg','image/png'=>'png','image/gif'=>'gif','image/webp'=>'webp'][$info['mime']]??null;
        if(!$ext) $out(['error'=>'format non supporté (jpg, png, gif, webp)'],422);
        $dir=$prepUploadDir();
        if(!is_writable($dir)) $out(['error'=>'dossier uploads/ non inscriptible (chmod 755)'],500);
        $name=bin2hex(random_bytes(8)).'.'.$ext;
        if(!move_uploaded_file($f['tmp_name'],"$dir/$name")) $out(['error'=>'écriture impossible'],500);
        $out(['url'=>'uploads/'.$name],201);

      /* --- upload de document (pièce jointe) : whitelist d'extensions, jamais exécutable --- */
      case 'upload_doc':
        if(empty($_FILES['file'])||$_FILES['file']['error']!==UPLOAD_ERR_OK) $out(['error'=>'aucun fichier reçu'],400);
        $f=$_FILES['file'];
        if($f['size']>25*1024*1024) $out(['error'=>'fichier trop grand (max 25 Mo)'],422);
        $allow=['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','csv','rtf','odt','ods','odp','json','xml','md','log'];
        $orig=(string)($f['name']??'file');
        $ext=strtolower(pathinfo($orig,PATHINFO_EXTENSION));
        if(!in_array($ext,$allow,true)) $out(['error'=>'extension non autorisée ('.implode(', ',$allow).')'],422);
        // nom d'affichage nettoyé (sécurisé pour l'attribut download)
        $clean=preg_replace('/[^\w.\- ]+/u','_',pathinfo($orig,PATHINFO_FILENAME));
        $display=substr($clean,0,120).'.'.$ext;
        $dir=$prepUploadDir();
        if(!is_writable($dir)) $out(['error'=>'dossier uploads/ non inscriptible (chmod 755)'],500);
        $name=bin2hex(random_bytes(8)).'.'.$ext;
        if(!move_uploaded_file($f['tmp_name'],"$dir/$name")) $out(['error'=>'écriture impossible'],500);
        $out(['url'=>'uploads/'.$name,'name'=>$display],201);

      /* --- import JSON : ajoute nœuds+liens au projet courant (IDs remappés) --- */
      case 'import':
        $pid=(int)($body['project_id']??1) ?: 1;
        $inN=$body['nodes']??[]; $inL=$body['links']??[];
        if(!is_array($inN)||!is_array($inL)) $out(['error'=>'format JSON invalide (nodes/links attendus)'],422);
        if(count($inN)>5000) $out(['error'=>'import trop volumineux (max 5000 nœuds)'],422);
        $pdo=db(); $pdo->beginTransaction();
        try{
          $map=[];
          $insN=$pdo->prepare("INSERT INTO nodes (project_id,type,label,value,importance,statut,confidence,source,image,file_url,file_name,note,x,y)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
          foreach($inN as $n){
            if(!is_array($n)) continue;
            if(trim((string)($n['label']??''))==='') continue;
            $insN->execute(array_merge([$pid],$sanitizeNode($n),[
              isset($n['x'])&&is_numeric($n['x'])?(float)$n['x']:null, isset($n['y'])&&is_numeric($n['y'])?(float)$n['y']:null,
            ]));
            if(isset($n['id'])) $map[(int)$n['id']]=(int)$pdo->lastInsertId();
          }
          $insL=$pdo->prepare("INSERT INTO links (project_id,source,target,label,confidence) VALUES (?,?,?,?,?)");
          $lc=0;
          foreach($inL as $l){
            if(!is_array($l)) continue;
            $s=$map[(int)($l['source']??0)]??null; $t=$map[(int)($l['target']??0)]??null;
            if(!$s||!$t||$s===$t) continue;
            $insL->execute([$pid,$s,$t,substr((string)($l['label']??''),0,120) ?: null,$cf($l['confidence']??null)]); $lc++;
          }
          $pdo->commit();
          $out(['ok'=>true,'nodes'=>count($map),'links'=>$lc],201);
        }catch(Throwable $e){ $pdo->rollBack(); $out(['error'=>'import échoué: '.$e->getMessage()],500); }

      default: $out(['error'=>'action inconnue'],404);
    }
  } catch(Throwable $e){ $out(['error'=>$e->getMessage()],500); }
}

/* =============================================================
   PAGE
   ============================================================= */
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Detective : plateforme d'investigation OSINT, cartographie en graphe des cibles, entités et relations.">
<title>Detective</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><circle cx='13' cy='13' r='9' fill='none' stroke='%2345c4b0' stroke-width='3.5'/><line x1='20' y1='20' x2='29' y2='29' stroke='%2345c4b0' stroke-width='3.5' stroke-linecap='round'/></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0e1116;--bg-alt:#141922;--panel:#1a1f27;--panel-2:#212832;
  --border:#2a3038;--border-strong:#3a4450;
  --text:#e9eaee;--text-mid:#8d96a3;--text-dim:#565f6b;
  --accent:#45c4b0;--critique:#e5484d;--eleve:#f0883e;--faible:#6e7f92;--ok:#4caf7d;
  --mono:'IBM Plex Mono',ui-monospace,Consolas,monospace;
}
*{box-sizing:border-box;}
html,body{height:100%;}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;overflow:hidden;}
@media(prefers-reduced-motion:reduce){*{transition:none!important;}}
.app{display:flex;flex-direction:column;height:100vh;}
.top{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg-alt);flex:none;flex-wrap:wrap;}
.top h1{font-size:14.5px;margin:0;font-weight:700;}
.top .sp{flex:1;}
/* segmented control des vues */
.seg{display:flex;border:1px solid var(--border-strong);border-radius:6px;overflow:hidden;}
.seg button{background:var(--panel);border:none;border-right:1px solid var(--border-strong);color:var(--text-mid);font-family:var(--mono);font-size:11.5px;padding:6px 13px;cursor:pointer;transition:.12s;}
.seg button:last-child{border-right:none;}
.seg button:hover{color:var(--text);}
.seg button.on{background:var(--accent);color:#0e1116;font-weight:700;}
.search{background:var(--panel);border:1px solid var(--border-strong);color:var(--text);font-family:var(--mono);font-size:11.5px;padding:6px 11px;border-radius:5px;width:230px;transition:.12s;}
.search:focus{outline:none;border-color:var(--accent);width:260px;}
.search::placeholder{color:var(--text-dim);}
.fwrap{position:relative;}
#fBadge{margin-left:5px;font-size:10px;color:#0e1116;background:var(--accent);border-radius:8px;padding:0 5px;display:none;}
#fBadge.on{display:inline;}
.fpop{position:absolute;top:34px;left:0;z-index:40;display:none;background:var(--panel);border:1px solid var(--border-strong);border-radius:8px;padding:12px;width:230px;box-shadow:0 12px 30px rgba(0,0,0,.5);}
.fpop.open{display:block;}
.fpop-h{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin:8px 0 6px;display:flex;align-items:center;gap:8px;}
.fpop-h:first-child{margin-top:0;}
.lnk{background:none;border:none;color:var(--accent);font-family:var(--mono);font-size:10px;cursor:pointer;padding:0;text-decoration:underline;margin-left:auto;}
.lnk+.lnk{margin-left:6px;}
.fchecks{display:flex;flex-direction:column;gap:3px;}
.fchecks label{display:flex;align-items:center;gap:7px;font-size:11.5px;color:var(--text-mid);cursor:pointer;padding:2px 0;}
.fchecks input{accent-color:var(--accent);cursor:pointer;}
.cnt{font-size:11px;color:var(--text-dim);}
.upl{display:flex;gap:8px;align-items:center;margin-top:6px;}
.upl input[type=file]{font-size:10.5px;color:var(--text-mid);flex:1;}
.upl-st{font-size:10.5px;color:var(--text-dim);}
.nprev{display:none;width:100%;height:120px;object-fit:cover;border-radius:6px;margin-top:8px;border:1px solid var(--border-strong);}
.btn{background:var(--panel-2);border:1px solid var(--border-strong);color:var(--text);font-family:var(--mono);font-size:11.5px;padding:6px 12px;border-radius:5px;cursor:pointer;transition:.12s;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn-p{background:var(--accent);border-color:var(--accent);color:#0e1116;font-weight:700;}
.btn-p:hover{filter:brightness(1.1);color:#0e1116;}
.st{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(10px);background:var(--panel-2);border:1px solid var(--border-strong);color:var(--text-mid);font-family:var(--mono);font-size:12.5px;padding:0;border-radius:7px;opacity:0;pointer-events:none;transition:opacity .18s,transform .18s;z-index:80;box-shadow:0 10px 30px rgba(0,0,0,.4);}
.st:not(:empty){padding:9px 16px;opacity:1;transform:translateX(-50%) translateY(0);}
.st.ok{color:var(--ok);border-color:rgba(76,175,125,.5);}.st.err{color:var(--critique);border-color:rgba(229,72,77,.5);}
.st.load{color:var(--accent);border-color:rgba(69,196,176,.5);}
.main{flex:1;display:flex;min-height:0;}
.cv{flex:1;position:relative;overflow:hidden;cursor:grab;touch-action:none;background:radial-gradient(rgba(255,255,255,.05) 1px,transparent 1px);background-size:24px 24px;}
.cv.pan{cursor:grabbing;}
#svg{position:absolute;inset:0;width:100%;height:100%;}
.ln{stroke:rgba(255,255,255,.16);stroke-width:1.3;}
.ln.critique{stroke:rgba(229,72,77,.6);}.ln.eleve{stroke:rgba(240,136,62,.5);}
.ln.lacune{stroke:#3a4450;stroke-dasharray:3 4;opacity:.7;}.ln.exclu{stroke:rgba(76,175,125,.45);stroke-dasharray:2 4;}
.ln.dim{opacity:.07;}
.lnl{fill:var(--text-mid);font-size:9.5px;pointer-events:none;}
.lnl.dim{opacity:.08;}
.hd{fill:var(--text-dim);font-size:11px;font-weight:700;text-anchor:middle;letter-spacing:.04em;text-transform:uppercase;}
.nd{cursor:pointer;}
.ndr{fill:var(--panel);stroke-width:1.5px;}
.ndi{text-anchor:middle;dominant-baseline:central;font-size:12px;}
.ndt{fill:var(--text);font-size:10.5px;text-anchor:middle;dominant-baseline:central;}
.nd.sel .ndr{stroke:#fff!important;stroke-width:2.5px;}
.nd.lk .ndr{stroke:var(--accent)!important;stroke-dasharray:4 3;}
.nd.dim{opacity:.18;}
.nd .pic{opacity:.9;}
.side{width:300px;flex:none;border-left:1px solid var(--border);background:var(--panel);overflow-y:auto;padding:16px;}
.empty{color:var(--text-dim);font-size:12px;line-height:1.6;}
.flag{display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;margin-bottom:9px;font-weight:700;}
.f-critique{background:rgba(229,72,77,.15);color:#ff9599;}.f-eleve{background:rgba(240,136,62,.15);color:#ffb27a;}
.f-normal{background:rgba(69,196,176,.15);color:#7be3d1;}.f-faible{background:rgba(110,128,152,.15);color:#aab6c6;}
.f-lacune{background:rgba(86,95,107,.18);color:#8d96a3;}.f-exclu{background:rgba(76,175,125,.15);color:#8fe0b6;}
.pimg{width:100%;height:150px;object-fit:cover;border-radius:8px;border:1px solid var(--border-strong);margin-bottom:10px;background:var(--bg-alt);}
.dl{font-size:14px;font-weight:700;word-break:break-word;}
.dt{font-size:10.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px;}
.dr{display:flex;justify-content:space-between;gap:10px;font-size:11.5px;color:var(--text-mid);padding:5px 0;border-top:1px solid var(--border);}
.dr b{color:var(--text);font-weight:500;text-align:right;word-break:break-word;}
.dr a{color:var(--accent);word-break:break-all;}
.dn{font-size:12px;color:var(--text-mid);line-height:1.5;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);}
.dnbr{font-size:10.5px;color:var(--text-dim);margin-top:12px;padding-top:10px;border-top:1px solid var(--border);}
.dnbr b{color:var(--text-mid);}
.da{display:flex;gap:8px;margin-top:16px;}.da .btn{flex:1;text-align:center;}
.btn-d{border-color:rgba(229,72,77,.4);color:#ff9599;}.btn-d:hover{background:rgba(229,72,77,.12);color:#ff9599;}
.fld{margin-bottom:10px;}
.fld label{display:block;font-size:10.5px;color:var(--text-dim);margin-bottom:4px;text-transform:uppercase;}
.fld input,.fld select,.fld textarea{width:100%;background:var(--bg-alt);border:1px solid var(--border-strong);color:var(--text);font-family:var(--mono);font-size:12px;padding:7px 9px;border-radius:5px;}
.fld textarea{resize:vertical;min-height:50px;}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:50;}
.ov.open{display:flex;}
.md{background:var(--panel);border:1px solid var(--border-strong);border-radius:12px;padding:22px;width:min(440px,92vw);max-height:88vh;overflow-y:auto;}
.md h3{margin:0 0 16px;font-size:14px;}
.mda{display:flex;gap:10px;justify-content:flex-end;margin-top:16px;}
.leg{display:flex;gap:12px;flex-wrap:wrap;align-items:center;padding:7px 16px;border-top:1px solid var(--border);background:var(--bg-alt);flex:none;font-size:10.5px;color:var(--text-mid);}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;vertical-align:middle;}
.hint{color:var(--text-dim);margin-left:auto;}
.docinfo{font-size:11px;color:var(--accent);margin-top:6px;word-break:break-all;}
.docinfo a{color:var(--accent);}
.sbadge{display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;margin-bottom:9px;margin-left:6px;font-weight:700;}
.ddl{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:7px 10px;border:1px solid var(--border-strong);border-radius:6px;font-size:11.5px;color:var(--accent);text-decoration:none;word-break:break-all;}
.ddl:hover{border-color:var(--accent);background:rgba(69,196,176,.08);}
.qadd{width:100%;margin-top:8px;background:var(--panel-2);border:1px dashed var(--border-strong);color:var(--text-mid);font-family:var(--mono);font-size:11.5px;padding:7px;border-radius:5px;cursor:pointer;}
.qadd:hover{border-color:var(--accent);color:var(--accent);}
.qlink-fld{display:none;}
.qlink-fld.on{display:block;}
.smark{font-size:11px;font-weight:700;}
.proj{display:flex;align-items:center;gap:6px;}
.proj select{background:var(--panel);border:1px solid var(--border-strong);color:var(--text);font-family:var(--mono);font-size:12px;padding:6px 9px;border-radius:5px;font-weight:600;max-width:200px;}
.proj .micro{background:none;border:1px solid var(--border-strong);color:var(--text-mid);font-family:var(--mono);font-size:13px;line-height:1;padding:4px 8px;border-radius:5px;cursor:pointer;}
.proj .micro:hover{border-color:var(--accent);color:var(--accent);}
.dr-link{align-items:center;}
.lx{background:none;border:none;color:var(--text-dim);font-size:15px;line-height:1;cursor:pointer;padding:0 2px;margin-left:6px;}
.lx:hover{color:var(--critique);}
.sum{font-size:12px;}
.sum h4{font-size:10.5px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin:14px 0 8px;}
.sum h4:first-child{margin-top:4px;}
.sum-row{display:flex;align-items:center;gap:8px;padding:3px 0;color:var(--text-mid);}
.sum-row .bar{height:6px;border-radius:3px;flex:none;min-width:6px;}
.sum-row .lab{flex:1;}
.sum-row .num{color:var(--text);font-weight:600;}
.sum-total{font-size:11px;color:var(--text-dim);margin-top:12px;padding-top:10px;border-top:1px solid var(--border);}

.fld-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.fld-row .fld{margin-bottom:10px;}
.fld-details{margin-bottom:10px;border:1px solid var(--border-strong);border-radius:6px;padding:0 10px;}
.fld-details summary{padding:9px 0;font-size:10.5px;color:var(--text-dim);cursor:pointer;list-style:none;text-transform:uppercase;letter-spacing:.04em;}
.fld-details summary::-webkit-details-marker{display:none;}
.fld-details summary::before{content:'▸ ';color:var(--accent);}
.fld-details[open] summary::before{content:'▾ ';}
.fld-details[open]{padding-bottom:12px;}
.noresults{position:absolute;top:16px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--border-strong);border-radius:8px;padding:10px 16px;font-size:12.5px;color:var(--text-mid);z-index:10;display:flex;align-items:center;gap:10px;box-shadow:0 10px 24px rgba(0,0,0,.35);white-space:nowrap;}
.lnk2{background:none;border:none;color:var(--accent);font-family:var(--mono);font-size:12px;cursor:pointer;text-decoration:underline;padding:0;white-space:nowrap;}

@media (max-width:760px){
  .main{flex-direction:column;}
  .side{width:auto;height:38vh;flex:none;border-left:none;border-top:1px solid var(--border);}
  .search{width:140px;}
  .search:focus{width:170px;}
  .top{gap:8px;padding:8px 10px;}
  .proj select{max-width:120px;}
  .noresults{white-space:normal;max-width:88vw;text-align:center;}
}
@media (max-width:460px){
  .seg button{padding:6px 9px;font-size:11px;}
  .search{width:110px;}
  .fld-row{grid-template-columns:1fr;gap:0;}
}
</style>
</head>
<body>
<div class="app">
  <div class="top">
    <h1 title="Detective : plateforme d'investigation OSINT">Detective</h1>
    <div class="proj">
      <select id="projSel" title="Mission active"></select>
      <button class="micro" id="bProjAdd" title="Nouvelle mission">＋</button>
      <button class="micro" id="bProjDel" title="Supprimer cette mission">🗑</button>
    </div>
    <div class="seg" id="seg">
      <button data-v="ensemble" class="on">Vue d'ensemble</button>
      <button data-v="organisee">Vue organisée</button>
      <button data-v="schema">Vue schéma</button>
    </div>
    <input class="search" id="search" placeholder="rechercher : nom, IP, site, e-mail, note…" autocomplete="off">
    <div class="fwrap">
      <button class="btn" id="bFilter">Filtres<span id="fBadge"></span></button>
      <div class="fpop" id="fpop">
        <div class="fpop-h">Types <button class="lnk" data-all="type">tout</button><button class="lnk" data-none="type">aucun</button></div>
        <div id="fTypes" class="fchecks"></div>
        <div class="fpop-h">Importance <button class="lnk" data-all="imp">tout</button><button class="lnk" data-none="imp">aucun</button></div>
        <div id="fImp" class="fchecks"></div>
        <div class="fpop-h">Statut <button class="lnk" data-all="stat">tout</button><button class="lnk" data-none="stat">aucun</button></div>
        <div id="fStat" class="fchecks"></div>
      </div>
    </div>
    <span class="st" id="st"></span>
    <span class="cnt" id="cnt"></span>
    <div class="sp"></div>
    <button class="btn" id="bLink">+ lien</button>
    <button class="btn btn-p" id="bNode">+ nœud</button>
    <div class="fwrap">
      <button class="btn" id="bMore">⋯ plus</button>
      <div class="fpop" id="morePop">
        <button class="btn" id="bImport" style="width:100%;margin-bottom:6px;text-align:left">⤒ importer un fichier</button>
        <button class="btn" id="bExport" style="width:100%;margin-bottom:6px;text-align:left">⤓ exporter la mission</button>
        <button class="btn" id="bFit" style="width:100%;margin-bottom:6px;text-align:left">⊡ ajuster la vue</button>
        <button class="btn" id="bLayout" style="width:100%;text-align:left">↻ relancer le layout</button>
      </div>
    </div>
  </div>
  <input type="file" id="importFile" accept="application/json,.json" style="display:none">
  <div class="main">
    <div class="cv" id="cv"><svg id="svg">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill="rgba(255,255,255,.35)"/>
        </marker>
      </defs>
      <g id="vp"><g id="eL"></g><g id="hL"></g><g id="nL"></g></g>
    </svg>
    <div class="noresults" id="noResults" style="display:none">Aucun résultat pour « <span id="noResultsQ"></span> » <button class="lnk2" id="clearSearch">effacer</button></div>
    </div>
    <aside class="side" id="side"><div class="empty">Sélectionnez un nœud.<br><br>glisser = déplacer · maj+clic ×2 = créer un lien · survol = isoler les connexions · molette = zoom.</div></aside>
  </div>
  <div class="leg" id="leg"></div>
</div>

<!-- modal nœud -->
<div class="ov" id="ovN"><div class="md">
  <h3 id="nT">Nouveau nœud</h3>
  <div class="fld"><label>Libellé</label><input id="nLabel" maxlength="120" placeholder="ex: Jean Dupont / exemple.com"></div>
  <div class="fld"><label>Type</label><select id="nType"></select></div>
  <div class="fld"><label>Valeur complète</label><input id="nValue" maxlength="500" placeholder="URL, e-mail, n° tél, adresse…"></div>
  <div class="fld-row">
    <div class="fld"><label>Importance</label><select id="nImp">
      <option value="normal">normal</option><option value="eleve">élevé</option><option value="critique">critique</option>
      <option value="faible">faible</option><option value="lacune">lacune</option><option value="exclu">exclu</option></select></div>
    <div class="fld"><label>Statut</label><select id="nStat">
      <option value="a_verifier">à vérifier</option><option value="en_cours">en cours</option>
      <option value="confirme">confirmé</option><option value="vuln">vulnérabilité</option>
      <option value="rien">rien découvert</option><option value="ecarte">écarté</option></select></div>
    <div class="fld"><label>Confiance</label><select id="nConf"><option value="h">élevée</option><option value="m" selected>moyenne</option><option value="l">faible</option></select></div>
  </div>
  <div class="fld"><label>Source (URL)</label><input id="nSrc" maxlength="500" placeholder="https://…"></div>
  <details class="fld-details" id="imgDetails">
    <summary>Image (optionnel) : URL ou téléversement</summary>
    <div class="fld" style="margin-top:8px">
      <input id="nImg" maxlength="500" placeholder="https://…/photo.jpg  (ou choisir un fichier)">
      <div class="upl"><input type="file" id="nFile" accept="image/png,image/jpeg,image/gif,image/webp"><span class="upl-st" id="nUp"></span></div>
      <img class="nprev" id="nPrev" alt="">
    </div>
  </details>
  <details class="fld-details" id="docDetails">
    <summary>Pièce jointe (optionnel) : document PDF, Office, txt…</summary>
    <div class="fld" style="margin-top:8px">
      <div class="upl"><input type="file" id="nDoc" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.rtf,.odt,.ods,.odp,.json,.xml,.md,.log"><span class="upl-st" id="nDocSt"></span></div>
      <div id="nDocInfo" class="docinfo"></div>
    </div>
  </details>
  <div class="fld"><label>Note</label><textarea id="nNote" maxlength="5000"></textarea></div>
  <div class="fld qlink-fld" id="qlinkFld"><label>Libellé du lien vers ce nouvel élément</label><input id="qlinkLbl" maxlength="120" placeholder="ex: possède, ami de, héberge, résout vers"></div>
  <div class="mda"><button class="btn" id="nCancel">annuler</button><button class="btn btn-p" id="nSave">enregistrer</button></div>
</div></div>

<!-- modal lien -->
<div class="ov" id="ovL"><div class="md">
  <h3>Nouveau lien</h3>
  <div class="fld"><label>De</label><select id="lSrc"></select></div>
  <div class="fld"><label>Libellé</label><input id="lLabel" maxlength="120" placeholder="ex: employé de, héberge, utilise, possède"></div>
  <div class="fld"><label>Vers</label><select id="lTgt"></select></div>
  <div class="fld"><label>Confiance</label><select id="lConf"><option value="h">élevée</option><option value="m" selected>moyenne</option><option value="l">faible</option></select></div>
  <div class="mda"><button class="btn" id="lCancel">annuler</button><button class="btn btn-p" id="lSave">créer</button></div>
</div></div>

<script>
/* types : ordre = ordre des colonnes en vue organisée/schéma */
const TYPES=[
  ['organisation','Organisation','▪','c9a15a'],
  ['personne','Personne','☉','e0679a'],
  ['domaine','Domaine','▣','45c4b0'],
  ['subdomain','Sous-domaine','▤','3fa8c9'],
  ['email','E-mail','✉','9b8cf0'],
  ['telephone','Téléphone','☎','c98a5a'],
  ['adresse','Adresse','⌖','e08a5a'],
  ['alias','Alias / pseudo','◇','b48ce0'],
  ['social','Réseau social','◈','5aa9e0'],
  ['technologie','Technologie','⚙','e5c07b'],
  ['service','Service / App','▲','e0884a'],
  ['ip','IP / Infra','⌁','7ea36b'],
  ['image','Image','▨','d08a9a'],
  ['document','Document','▦','a0a8b4'],
  ['lacune','Lacune','◌','565f6b'],
  ['exclu','Exclu','✕','4caf7d'],
  ['autre','Autre','●','8d96a3'],
];
const ICON={},COLOR={},TLABEL={},TORDER={};
TYPES.forEach(([k,l,i,c],idx)=>{ICON[k]=i;TLABEL[k]=l;COLOR[k]=c;TORDER[k]=idx;});
const CONF={h:'Élevée',m:'Moyenne',l:'Faible'};
const FLAG={critique:'CRITIQUE',eleve:'ÉLEVÉ',normal:'NORMAL',faible:'FAIBLE',lacune:'LACUNE',exclu:'EXCLU'};
/* statut d'investigation : [libellé, couleur, marqueur affiché sur le nœud] */
const STATUT={
  a_verifier:['à vérifier','8d96a3',''],
  en_cours:['en cours','e5c07b','◔'],
  confirme:['confirmé','4caf7d','✓'],
  vuln:['vulnérabilité','e5484d','⚠'],
  rien:['rien / inutile','565f6b','∅'],
  ecarte:['écarté','6e7f92','–'],
};

let nodes=[],links=[],sel=null,editId=null,linkSrc=null,sim=null,hoverId=null,view='ensemble';
let curProject=1, projects=[];
let searchQ='',fTypes=new Set(),fImp=new Set(),fStat=new Set();  // Set vide = "tous"
let linkFrom=null, docUp={url:'',name:''};
const $=s=>document.querySelector(s);

/* un nœud passe-t-il les filtres ? (type ET importance) */
function passFilter(n){
  return (fTypes.size===0||fTypes.has(n.type))
      && (fImp.size===0||fImp.has(n.importance))
      && (fStat.size===0||fStat.has(n.statut||'a_verifier'));
}
/* un nœud correspond-il à la recherche ? (nom, valeur, note, type) */
function matchSearch(n){
  if(!searchQ) return true;
  const q=searchQ.toLowerCase();
  return (n.label&&n.label.toLowerCase().includes(q))
      || (n.value&&n.value.toLowerCase().includes(q))
      || (n.note&&n.note.toLowerCase().includes(q))
      || (TLABEL[n.type]&&TLABEL[n.type].toLowerCase().includes(q))
      || (n.type&&n.type.toLowerCase().includes(q));
}
/* nœuds visibles = ceux qui passent les filtres */
function vnodes(){ return nodes.filter(passFilter); }
/* rafraîchit : redessine (ensemble) ou relance la disposition (organisée/schéma) */
function refresh(){ if(view==='ensemble') draw(); else applyView(); updateCount(); }
function updateCount(){
  const vis=vnodes(), matched=searchQ?vis.filter(matchSearch).length:vis.length;
  $('#cnt').textContent = (fTypes.size||fImp.size||fStat.size||searchQ)
    ? `${matched}/${nodes.length} nœuds` : `${nodes.length} nœuds`;
  const nr=$('#noResults');
  if(searchQ&&vis.length&&matched===0){$('#noResultsQ').textContent=searchQ;nr.style.display='flex';}
  else nr.style.display='none';
}
/* résumé de la mission (affiché quand aucun nœud n'est sélectionné) */
function showSummary(){
  if(!nodes.length){$('#side').innerHTML='<div class="empty">Mission vide. Ajoute un premier nœud (+ nœud) ou importe un fichier.</div>';return;}
  const byType={},byStat={};
  nodes.forEach(n=>{byType[n.type]=(byType[n.type]||0)+1;const s=n.statut||'a_verifier';byStat[s]=(byStat[s]||0)+1;});
  const max=Math.max(...Object.values(byType));
  const typeRows=Object.keys(byType).sort((a,b)=>byType[b]-byType[a]).map(t=>
    `<div class="sum-row"><span class="bar" style="width:${6+40*byType[t]/max}px;background:#${COLOR[t]||'8d96a3'}"></span><span class="lab">${TLABEL[t]||t}</span><span class="num">${byType[t]}</span></div>`).join('');
  const statOrder=['vuln','confirme','en_cours','a_verifier','rien','ecarte'];
  const statRows=statOrder.filter(s=>byStat[s]).map(s=>
    `<div class="sum-row"><span class="smark" style="color:#${STATUT[s][1]}">${STATUT[s][2]||'·'}</span><span class="lab">${STATUT[s][0]}</span><span class="num">${byStat[s]}</span></div>`).join('');
  $('#side').innerHTML=`<div class="sum">
    <h4>Par type</h4>${typeRows}
    <h4>Par statut</h4>${statRows}
    <div class="sum-total">${nodes.length} nœuds · ${links.length} liens</div>
    <div class="empty" style="margin-top:12px">Sélectionne un nœud pour le détail.</div>
  </div>`;
}
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function st(t,c=''){const e=$('#st');e.textContent=t;e.className='st '+c;if(t)setTimeout(()=>{if(e.textContent===t){e.textContent='';e.className='st';}},2500);}
async function api(a,o={}){const r=await fetch('?api='+a,{headers:{'Content-Type':'application/json'},...o});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;}

/* remplit le select de type du modal */
(function(){$('#nType').innerHTML=TYPES.map(([k,l])=>`<option value="${k}">${l}</option>`).join('');})();

async function loadProjects(){
  projects=await api('projects');
  if(!projects.length){projects=[{id:1,name:'Mission 1',target:'',nodes:0}];}
  if(!projects.find(p=>p.id===curProject))curProject=projects[0].id;
  $('#projSel').innerHTML=projects.map(p=>
    `<option value="${p.id}"${p.id===curProject?' selected':''}>${esc(p.name)}${p.target?', '+esc(p.target):''} (${p.nodes})</option>`).join('');
}
async function load(){
  const g=await api('graph&project='+curProject);
  const W=$('#cv').clientWidth,H=$('#cv').clientHeight;
  nodes=g.nodes.map(n=>({...n,x:n.x??(W/2+(Math.random()-.5)*W*.6),y:n.y??(H/2+(Math.random()-.5)*H*.6),vx:0,vy:0,pinned:n.x!=null}));
  const by=Object.fromEntries(nodes.map(n=>[n.id,n]));
  links=g.links.filter(l=>by[l.source]&&by[l.target]).map(l=>({...l,s:by[l.source],t:by[l.target]}));
  legend();applyView();
  if(!sel)showSummary();
}
async function switchProject(pid){
  curProject=pid;sel=null;hoverId=null;
  st('chargement…','load');
  await load();updateCount();
}
async function newProject(){
  const name=prompt('Nom de la mission ?');if(!name||!name.trim())return;
  const target=prompt('Cible principale (domaine, nom…), optionnel :')||'';
  try{
    const r=await api('add_project',{method:'POST',body:JSON.stringify({name:name.trim(),target:target.trim()})});
    await loadProjects();$('#projSel').value=r.id;await switchProject(r.id);st('mission créée','ok');
  }catch(e){st(e.message,'err');}
}
async function deleteProject(){
  const p=projects.find(x=>x.id===curProject);if(!p)return;
  if(p.id===1){st('mission initiale non supprimable','err');return;}
  if(!confirm(`Supprimer la mission « ${p.name} » et TOUT son contenu ?`))return;
  try{
    await api('del_project&id='+p.id,{method:'POST'});
    await loadProjects();curProject=projects[0].id;$('#projSel').value=curProject;
    await switchProject(curProject);st('mission supprimée','ok');
  }catch(e){st(e.message,'err');}
}

/* ---------- ensembles de voisinage (pour survol) ---------- */
function neighbors(id){
  const s=new Set([id]);
  for(const l of links){ if(l.source===id)s.add(l.target); if(l.target===id)s.add(l.source); }
  return s;
}

/* ---------- LES 3 VUES ---------- */
function applyView(){
  if(sim){cancelAnimationFrame(sim);sim=null;}
  $('#hL').innerHTML='';
  if(view==='ensemble')      startSim();
  else if(view==='organisee') layoutOrganized();
  else                        layoutSchema();
}

/* vue d'ensemble : physique, nœuds + liens */
function startSim(){
  let tk=0;const W=$('#cv').clientWidth,H=$('#cv').clientHeight;
  (function step(){
    const k=.0016,rep=5200,sp=.008,LEN=130;
    for(let i=0;i<nodes.length;i++){const a=nodes[i];if(a===drag)continue;
      a.vx+=(W/2-a.x)*k;a.vy+=(H/2-a.y)*k;
      for(let j=0;j<nodes.length;j++){if(i===j)continue;const b=nodes[j];
        let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.01,d=Math.sqrt(d2),f=rep/d2;a.vx+=dx/d*f;a.vy+=dy/d*f;}}
    for(const e of links){let dx=e.t.x-e.s.x,dy=e.t.y-e.s.y,d=Math.sqrt(dx*dx+dy*dy)+.01,f=(d-LEN)*sp;
      if(e.s!==drag&&!e.s.pinned){e.s.vx+=dx/d*f;e.s.vy+=dy/d*f;}
      if(e.t!==drag&&!e.t.pinned){e.t.vx-=dx/d*f;e.t.vy-=dy/d*f;}}
    for(const a of nodes){if(a===drag||a.pinned)continue;a.x+=a.vx*=.82;a.y+=a.vy*=.82;
      a.x=Math.max(50,Math.min(W-50,a.x));a.y=Math.max(40,Math.min(H-40,a.y));}
    draw();if(++tk<600)sim=requestAnimationFrame(step);
  })();
}

/* vue organisée : SEULEMENT les nœuds, en colonnes par type */
function layoutOrganized(){
  const W=$('#cv').clientWidth;
  const groups={};
  vnodes().forEach(n=>{(groups[n.type]=groups[n.type]||[]).push(n);});
  const cols=Object.keys(groups).sort((a,b)=>(TORDER[a]??99)-(TORDER[b]??99));
  const CW=210, x0=120, y0=90, GY=70;
  cols.forEach((type,ci)=>{
    const x=x0+ci*CW;
    groups[type].forEach((n,ri)=>{ n.x=x; n.y=y0+ri*GY; n.pinned=true; });
  });
  // en-têtes de colonnes
  $('#hL').innerHTML=cols.map((type,ci)=>{
    const x=x0+ci*CW;
    return `<text class="hd" x="${x}" y="${y0-40}">${esc(TLABEL[type]||type)}</text>`
         + `<text class="hd" x="${x}" y="${y0-25}" style="font-size:9px;fill:#${COLOR[type]}">${groups[type].length}</text>`;
  }).join('');
  draw(true); // true = masquer les liens
}

/* vue schéma : couches à partir de la racine, liens fléchés lisibles */
function layoutSchema(){
  const W=$('#cv').clientWidth,H=$('#cv').clientHeight;
  const vis=vnodes(); if(!vis.length){draw();return;}
  const visSet=new Set(vis.map(n=>n.id));
  // racine = plus fort degré parmi les visibles
  let root=vis[0]; vis.forEach(n=>{if((n.degree||0)>(root.degree||0))root=n;});
  const depth={}; depth[root.id]=0;
  const adj={}; vis.forEach(n=>adj[n.id]=[]);
  links.forEach(l=>{ if(visSet.has(l.source)&&visSet.has(l.target)){adj[l.source].push(l.target);adj[l.target].push(l.source);} });
  const q=[root.id];
  while(q.length){const id=q.shift();(adj[id]||[]).forEach(nx=>{if(depth[nx]===undefined){depth[nx]=depth[id]+1;q.push(nx);}});}
  let maxD=0; vis.forEach(n=>{if(depth[n.id]===undefined)depth[n.id]=99; else maxD=Math.max(maxD,depth[n.id]);});
  // les non-atteints (99) vont dans une colonne finale
  const layers={};
  vis.forEach(n=>{const d=depth[n.id]===99?maxD+1:depth[n.id];(layers[d]=layers[d]||[]).push(n);});
  const ds=Object.keys(layers).map(Number).sort((a,b)=>a-b);
  const CW=Math.max(230,(W-160)/Math.max(1,ds.length)), x0=110, GY=64;
  ds.forEach((d,ci)=>{
    const col=layers[d]; const x=x0+ci*CW;
    const totalH=(col.length-1)*GY; const y0=Math.max(70,H/2-totalH/2);
    col.forEach((n,ri)=>{ n.x=x; n.y=y0+ri*GY; n.pinned=true; });
  });
  draw();
}

const size=n=>20+Math.min(14,(n.degree||0)*2);
function draw(hideLinks=false){
  const dimSet=hoverId?neighbors(hoverId):null;
  const showLinks = !hideLinks && view!=='organisee';
  const arrow = view==='schema';
  const vis=nodes.filter(passFilter);
  const visSet=new Set(vis.map(n=>n.id));
  // un lien n'apparaît que si ses deux extrémités passent les filtres
  $('#eL').innerHTML = showLinks ? links.filter(e=>visSet.has(e.source)&&visSet.has(e.target)).map(e=>{
    let c='ln';const imp=e.t.importance,ims=e.s.importance;
    if(imp==='lacune'||ims==='lacune')c+=' lacune';else if(imp==='exclu'||ims==='exclu')c+=' exclu';
    else if(imp==='critique')c+=' critique';else if(imp==='eleve')c+=' eleve';
    const off = (dimSet && !(dimSet.has(e.source)&&dimSet.has(e.target)))
             || (searchQ && !(matchSearch(e.s)&&matchSearch(e.t)));
    if(off)c+=' dim';
    const mx=(e.s.x+e.t.x)/2,my=(e.s.y+e.t.y)/2;
    const mk=arrow?'marker-end="url(#arrow)"':'';
    let x2=e.t.x,y2=e.t.y;
    if(arrow){const dx=e.t.x-e.s.x,dy=e.t.y-e.s.y,d=Math.sqrt(dx*dx+dy*dy)||1,r=size(e.t)+4;x2=e.t.x-dx/d*r;y2=e.t.y-dy/d*r;}
    let lc='lnl'+(off?' dim':'');
    return `<line class="${c}" x1="${e.s.x}" y1="${e.s.y}" x2="${x2}" y2="${y2}" ${mk}></line>`
      +(e.label?`<text class="${lc}" x="${mx}" y="${my-3}" text-anchor="middle">${esc(e.label)}</text>`:'');
  }).join('') : '';
  $('#nL').innerHTML=vis.map(n=>{
    const r=size(n),ic=ICON[n.type]||'●';
    const stroke=n.importance==='critique'?'#e5484d':n.importance==='eleve'?'#f0883e':n.importance==='faible'?'#6e7f92':n.importance==='lacune'?'#455060':n.importance==='exclu'?'#4caf7d':('#'+(COLOR[n.type]||'8d96a3'));
    const dash=(n.importance==='lacune'||n.importance==='exclu')?'stroke-dasharray="4 3"':'';
    let cl='nd'+(sel===n.id?' sel':'')+(linkSrc===n.id?' lk':'');
    if(dimSet && !dimSet.has(n.id))cl+=' dim';
    const lb=n.label.length>18?n.label.slice(0,17)+'…':n.label;
    // vignette image intégrée si présente
    const pic = n.image ? `<clipPath id="cp${n.id}"><rect x="${-r+3}" y="${-r+3}" width="${2*r-6}" height="${2*r-6}" rx="5"/></clipPath>
       <image class="pic" href="${esc(n.image)}" x="${-r+3}" y="${-r+3}" width="${2*r-6}" height="${2*r-6}" preserveAspectRatio="xMidYMid slice" clip-path="url(#cp${n.id})"/>` : '';
    const iconTxt = n.image ? '' : `<text class="ndi" y="${-r+11}" style="fill:${stroke}">${esc(ic)}</text>`;
    // marqueur de statut (coin haut-droit) si statut ≠ "à vérifier"
    const stt=n.statut&&STATUT[n.statut]?n.statut:'a_verifier';
    const smk = (stt!=='a_verifier'&&STATUT[stt][2]) ?
      `<circle cx="${r-2}" cy="${-r+2}" r="7" fill="#${STATUT[stt][1]}" stroke="#0e1116" stroke-width="1.5"/>
       <text x="${r-2}" y="${-r+2}" text-anchor="middle" dominant-baseline="central" style="font-size:9px;fill:#0e1116;font-weight:700">${STATUT[stt][2]}</text>` : '';
    return `<g class="${cl}" data-id="${n.id}" transform="translate(${n.x},${n.y})">
      <rect class="ndr" x="${-r}" y="${-r}" width="${r*2}" height="${r*2}" rx="7" style="stroke:${stroke}" ${dash}></rect>
      ${pic}${iconTxt}
      <rect x="${-r}" y="${r-14}" width="${2*r}" height="14" rx="0" fill="rgba(14,17,22,.72)" ${n.image?'':'style="display:none"'}></rect>
      <text class="ndt" y="${n.image?r-6:4}">${esc(lb)}</text>${smk}</g>`;
  }).join('');
}

function legend(){
  $('#leg').innerHTML=['organisation','personne','domaine','email','telephone','adresse','alias','social','technologie','ip','image']
    .map(t=>`<span><span class="dot" style="background:#${COLOR[t]}"></span>${TLABEL[t]}</span>`).join('')
    +'<span class="hint">survol=isoler · glisser=déplacer · maj+clic ×2=lier</span>';
}

function select(id){
  sel=id;linkSrc=null;draw(view==='organisee');
  const n=nodes.find(x=>x.id===id);if(!n)return;
  const src=n.source?`<a href="${esc(n.source)}" target="_blank" rel="noopener">${esc(n.source)}</a>`:'N/A';
  const stt=n.statut&&STATUT[n.statut]?n.statut:'a_verifier';
  const stC=STATUT[stt][1];
  // liens de ce nœud, listés en clair, avec suppression individuelle
  const rel=links.filter(l=>l.source===id||l.target===id).map(l=>{
    const other=l.source===id?l.t:l.s; const dir=l.source===id?'→':'←';
    return `<div class="dr dr-link"><span>${dir} ${esc(l.label||'lié')}</span><b>${esc(other.label)}</b><button class="lx" data-lid="${l.id}" title="supprimer ce lien">×</button></div>`;
  }).join('');
  const doc=n.file_url?`<a class="ddl" href="${esc(n.file_url)}" download="${esc(n.file_name||'document')}" target="_blank" rel="noopener">⇩ ${esc(n.file_name||'télécharger le document')}</a>`:'';
  $('#side').innerHTML=`
    ${n.image?`<img class="pimg" src="${esc(n.image)}" alt="" onerror="this.style.display='none'">`:''}
    <div><span class="flag f-${n.importance}">${FLAG[n.importance]}</span><span class="sbadge" style="background:${stC}22;color:${stC}">${STATUT[stt][0].toUpperCase()}</span></div>
    <div class="dl">${esc(n.value||n.label)}</div>
    <div class="dt">${TLABEL[n.type]||n.type}</div>
    <div class="dr"><span>Confiance</span><b>${CONF[n.confidence]}</b></div>
    <div class="dr"><span>Connexions</span><b>${n.degree||0}</b></div>
    <div class="dr"><span>Source</span><b>${src}</b></div>
    ${doc}
    ${n.note?`<div class="dn">${esc(n.note)}</div>`:''}
    ${rel?`<div class="dnbr"><b>LIENS</b></div>${rel}`:''}
    <button class="qadd" id="pQ">+ ajouter un élément lié</button>
    <div class="da"><button class="btn" id="pE">modifier</button><button class="btn btn-d" id="pD">supprimer</button></div>`;
  $('#pQ').onclick=()=>openNode(null,n.id);
  $('#pE').onclick=()=>openNode(n);
  $('#pD').onclick=()=>delNode(n.id);
  $('#side').querySelectorAll('.lx').forEach(b=>b.onclick=()=>delLink(+b.dataset.lid,id));
}
async function delLink(lid,reselect){
  try{await api('del_link&id='+lid,{method:'POST'});st('lien supprimé','ok');await load();if(reselect)select(reselect);}
  catch(e){st(e.message,'err');}
}

function openNode(n=null, linkFromId=null){
  editId=n?n.id:null;
  linkFrom=linkFromId;   // si défini : à la sauvegarde, on crée aussi un lien depuis ce nœud
  docUp={url:'',name:''};
  const from=linkFromId?nodes.find(x=>x.id===linkFromId):null;
  $('#nT').textContent = n?'Modifier le nœud' : (from?('Élément lié à : '+from.label):'Nouveau nœud');
  $('#nLabel').value=n?n.label:'';$('#nType').value=n?n.type:'domaine';$('#nValue').value=n?(n.value||''):'';
  $('#nImp').value=n?n.importance:'normal';$('#nStat').value=n?(n.statut||'a_verifier'):'a_verifier';
  $('#nConf').value=n?n.confidence:'m';
  $('#nSrc').value=n?(n.source||''):'';$('#nImg').value=n?(n.image||''):'';$('#nNote').value=n?(n.note||''):'';
  $('#nFile').value='';$('#nUp').textContent='';showPrev(n?n.image:'');
  $('#nDoc').value='';$('#nDocSt').textContent='';
  if(n&&n.file_url){docUp={url:n.file_url,name:n.file_name||'document'};$('#nDocInfo').innerHTML=`<a href="${esc(n.file_url)}" target="_blank" rel="noopener">⇩ ${esc(n.file_name||'document')}</a>`;}
  else $('#nDocInfo').innerHTML='';
  // champ libellé du lien (seulement en mode ajout-lié)
  $('#qlinkFld').classList.toggle('on', !!linkFromId);
  if(linkFromId)$('#qlinkLbl').value='';
  $('#imgDetails').open = !!(n&&n.image);
  $('#docDetails').open = !!(n&&n.file_url);
  $('#ovN').classList.add('open');
}
function showPrev(u){const p=$('#nPrev');if(u){p.src=u;p.style.display='block';}else{p.style.display='none';}}
/* upload d'image → URL locale dans le champ image */
async function uploadFile(f){
  $('#nUp').textContent='envoi…';
  const fd=new FormData();fd.append('file',f);
  try{
    const r=await fetch('?api=upload',{method:'POST',body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.error||'échec');
    $('#nImg').value=d.url;showPrev(d.url);$('#nUp').textContent='✓ téléversé';
  }catch(e){$('#nUp').textContent='✗ '+e.message;}
}
/* upload de document → mémorisé dans docUp, attaché à la sauvegarde */
async function uploadDoc(f){
  $('#nDocSt').textContent='envoi…';
  const fd=new FormData();fd.append('file',f);
  try{
    const r=await fetch('?api=upload_doc',{method:'POST',body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.error||'échec');
    docUp={url:d.url,name:d.name};$('#nDocSt').textContent='✓';
    $('#nDocInfo').innerHTML=`<a href="${esc(d.url)}" target="_blank" rel="noopener">⇩ ${esc(d.name)}</a>`;
  }catch(e){$('#nDocSt').textContent='✗ '+e.message;}
}
async function saveNode(){
  const p={project_id:curProject,type:$('#nType').value,label:$('#nLabel').value.trim(),value:$('#nValue').value.trim(),
    importance:$('#nImp').value,statut:$('#nStat').value,confidence:$('#nConf').value,source:$('#nSrc').value.trim(),
    image:$('#nImg').value.trim(),file_url:docUp.url,file_name:docUp.name,note:$('#nNote').value.trim()};
  if(!p.label){st('libellé requis','err');return;}
  try{
    const r=await api(editId?('edit_node&id='+editId):'add_node',{method:'POST',body:JSON.stringify(p)});
    // mode ajout-lié : on relie le nouveau nœud au nœud d'origine
    if(!editId && linkFrom && r.id){
      await api('add_link',{method:'POST',body:JSON.stringify({source:linkFrom,target:r.id,label:$('#qlinkLbl').value.trim(),confidence:'m'})});
    }
    st(editId?'modifié':'ajouté','ok');$('#ovN').classList.remove('open');linkFrom=null;
    await load(); if(sel)select(sel);
  }catch(e){st(e.message,'err');}
}
async function delNode(id){
  if(!confirm('Supprimer ce nœud et ses liens ?'))return;
  try{await api('del_node&id='+id,{method:'POST'});st('supprimé','ok');
    sel=null;showSummary();await load();
  }catch(e){st(e.message,'err');}
}
function openLink(s=null,t=null){
  const o=nodes.map(n=>`<option value="${n.id}">${esc(n.label)}</option>`).join('');
  $('#lSrc').innerHTML=o;$('#lTgt').innerHTML=o;$('#lLabel').value='';
  if(s)$('#lSrc').value=s;if(t)$('#lTgt').value=t;
  $('#ovL').classList.add('open');
}
async function saveLink(){
  const p={source:+$('#lSrc').value,target:+$('#lTgt').value,label:$('#lLabel').value.trim(),confidence:$('#lConf').value};
  try{await api('add_link',{method:'POST',body:JSON.stringify(p)});st('lien créé','ok');$('#ovL').classList.remove('open');await load();
  }catch(e){st(e.message,'err');}
}

/* interactions canvas */
let drag=null,moved=false,pan=false,ps=null,view0={x:0,y:0,k:1};
const av=()=>$('#vp').setAttribute('transform',`translate(${view0.x},${view0.y}) scale(${view0.k})`);
function world(cx,cy){const r=$('#svg').getBoundingClientRect();return{x:(cx-r.left-view0.x)/view0.k,y:(cy-r.top-view0.y)/view0.k};}
$('#cv').addEventListener('mousedown',e=>{
  const g=e.target.closest('.nd');
  if(g){const id=+g.dataset.id,n=nodes.find(x=>x.id===id);
    if(e.shiftKey){if(linkSrc&&linkSrc!==id){openLink(linkSrc,id);linkSrc=null;draw(view==='organisee');}else{linkSrc=id;draw(view==='organisee');}return;}
    drag=n;moved=false;
  }else{pan=true;ps={x:e.clientX-view0.x,y:e.clientY-view0.y};$('#cv').classList.add('pan');}
});
window.addEventListener('mousemove',e=>{
  if(drag){const w=world(e.clientX,e.clientY);drag.x=w.x;drag.y=w.y;drag.vx=drag.vy=0;moved=true;draw(view==='organisee');}
  else if(pan){view0.x=e.clientX-ps.x;view0.y=e.clientY-ps.y;av();}
});
window.addEventListener('mouseup',async()=>{
  if(drag){if(moved){drag.pinned=true;try{await api('move&id='+drag.id,{method:'POST',body:JSON.stringify({x:drag.x,y:drag.y})});}catch(_){}}else select(drag.id);drag=null;}
  pan=false;$('#cv').classList.remove('pan');
});
/* survol = isoler les connexions */
$('#cv').addEventListener('mouseover',e=>{const g=e.target.closest('.nd');if(g){const id=+g.dataset.id;if(id!==hoverId){hoverId=id;draw(view==='organisee');}}});
$('#cv').addEventListener('mouseout',e=>{const g=e.target.closest('.nd');if(g&&!e.relatedTarget?.closest?.('.nd')){hoverId=null;draw(view==='organisee');}});
$('#cv').addEventListener('click',e=>{if(!e.target.closest('.nd')&&!pan){sel=null;linkSrc=null;draw(view==='organisee');showSummary();}});
$('#cv').addEventListener('wheel',e=>{e.preventDefault();const d=-Math.sign(e.deltaY)*.12,nk=Math.max(.35,Math.min(2.6,view0.k*(1+d)));const r=$('#svg').getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;view0.x=mx-(mx-view0.x)*(nk/view0.k);view0.y=my-(my-view0.y)*(nk/view0.k);view0.k=nk;av();},{passive:false});

/* tactile : glisser un nœud, glisser le vide pour déplacer la vue, pincer pour zoomer (parité tablette/téléphone) */
let pinch=null;
$('#cv').addEventListener('touchstart',e=>{
  if(e.touches.length===2){
    const[a,b]=e.touches;
    pinch={d:Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY),k:view0.k,mx:(a.clientX+b.clientX)/2,my:(a.clientY+b.clientY)/2,vx:view0.x,vy:view0.y};
    drag=null;pan=false;return;
  }
  const t=e.touches[0],g=e.target.closest('.nd');
  if(g){const id=+g.dataset.id;drag=nodes.find(x=>x.id===id);moved=false;}
  else{pan=true;ps={x:t.clientX-view0.x,y:t.clientY-view0.y};$('#cv').classList.add('pan');}
});
$('#cv').addEventListener('touchmove',e=>{
  if(pinch&&e.touches.length===2){
    const[a,b]=e.touches,d=Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY);
    const nk=Math.max(.35,Math.min(2.6,pinch.k*(d/pinch.d)));
    const r=$('#svg').getBoundingClientRect(),mx=pinch.mx-r.left,my=pinch.my-r.top;
    view0.x=mx-(mx-pinch.vx)*(nk/pinch.k);view0.y=my-(my-pinch.vy)*(nk/pinch.k);view0.k=nk;av();return;
  }
  if(!e.touches.length)return;
  const t=e.touches[0];
  if(drag){const w=world(t.clientX,t.clientY);drag.x=w.x;drag.y=w.y;drag.vx=drag.vy=0;moved=true;draw(view==='organisee');}
  else if(pan){view0.x=t.clientX-ps.x;view0.y=t.clientY-ps.y;av();}
});
$('#cv').addEventListener('touchend',()=>{
  pinch=null;
  if(drag){if(moved){drag.pinned=true;api('move&id='+drag.id,{method:'POST',body:JSON.stringify({x:drag.x,y:drag.y})}).catch(()=>{});}else select(drag.id);drag=null;}
  pan=false;$('#cv').classList.remove('pan');
});

/* commutateur de vues */
$('#seg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
  view=b.dataset.v;[...$('#seg').children].forEach(x=>x.classList.toggle('on',x===b));applyView();});

$('#bNode').onclick=()=>openNode();$('#bLink').onclick=()=>openLink();
$('#nCancel').onclick=()=>$('#ovN').classList.remove('open');$('#nSave').onclick=saveNode;
$('#lCancel').onclick=()=>$('#ovL').classList.remove('open');$('#lSave').onclick=saveLink;
$('#bLayout').onclick=()=>{if(view==='ensemble'){nodes.forEach(n=>n.pinned=false);}applyView();st('layout relancé','ok');};

/* --- upload / preview image dans le modal --- */
$('#nFile').onchange=e=>{const f=e.target.files[0];if(f)uploadFile(f);};
$('#nImg').oninput=()=>showPrev($('#nImg').value.trim());
$('#nDoc').onchange=e=>{const f=e.target.files[0];if(f)uploadDoc(f);};

/* --- export de la cartographie (JSON inspectable + réimportable) --- */
$('#bExport').onclick=()=>{
  const data={
    exported_at:new Date().toISOString(),
    nodes:nodes.map(n=>({id:n.id,type:n.type,label:n.label,value:n.value,importance:n.importance,
      statut:n.statut,confidence:n.confidence,source:n.source,image:n.image,
      file_url:n.file_url,file_name:n.file_name,note:n.note,x:n.x,y:n.y})),
    links:links.map(l=>({id:l.id,source:l.source,target:l.target,label:l.label,confidence:l.confidence}))
  };
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  const d=new Date().toISOString().slice(0,10);
  a.href=URL.createObjectURL(blob);a.download='detective-cartographie-'+d+'.json';a.click();
  URL.revokeObjectURL(a.href);
  st('cartographie exportée','ok');
};

/* --- import JSON dans la mission courante --- */
$('#bImport').onclick=()=>$('#importFile').click();
$('#importFile').onchange=async e=>{
  const f=e.target.files[0];if(!f)return;
  try{
    const txt=await f.text();
    const data=JSON.parse(txt);
    if(!data.nodes||!Array.isArray(data.nodes))throw new Error('fichier invalide (pas de "nodes")');
    if(!confirm(`Importer ${data.nodes.length} nœud(s) dans la mission courante ?`)){e.target.value='';return;}
    st('import en cours…','load');
    const r=await api('import',{method:'POST',body:JSON.stringify({project_id:curProject,nodes:data.nodes,links:data.links||[]})});
    st(`importé : ${r.nodes} nœuds, ${r.links} liens`,'ok');
    await loadProjects();await load();updateCount();
  }catch(err){st('import: '+err.message,'err');}
  e.target.value='';
};

/* --- ajuster la vue : recadre tous les nœuds à l'écran --- */
$('#bFit').onclick=()=>{
  const vis=vnodes();if(!vis.length)return;
  let minX=Infinity,minY=Infinity,maxX=-Infinity,maxY=-Infinity;
  vis.forEach(n=>{minX=Math.min(minX,n.x);minY=Math.min(minY,n.y);maxX=Math.max(maxX,n.x);maxY=Math.max(maxY,n.y);});
  const pad=60,W=$('#cv').clientWidth,H=$('#cv').clientHeight;
  const gw=(maxX-minX)||1,gh=(maxY-minY)||1;
  const k=Math.max(.35,Math.min(1.6,Math.min((W-2*pad)/gw,(H-2*pad)/gh)));
  view0.k=k;
  view0.x=(W-(minX+maxX)*k)/2;
  view0.y=(H-(minY+maxY)*k)/2;
  av();st('vue ajustée','ok');
};

/* --- recherche --- */
$('#search').addEventListener('input',e=>{searchQ=e.target.value.trim();draw(view==='organisee');updateCount();});
$('#clearSearch').onclick=()=>{searchQ='';$('#search').value='';draw(view==='organisee');updateCount();};

/* --- filtres : construction des cases + comportement --- */
function buildFilters(){
  $('#fTypes').innerHTML=TYPES.map(([k,l])=>
    `<label><input type="checkbox" data-t="${k}">${l}</label>`).join('');
  const imps=[['critique','critique'],['eleve','élevé'],['normal','normal'],['faible','faible'],['lacune','lacune'],['exclu','exclu']];
  $('#fImp').innerHTML=imps.map(([k,l])=>
    `<label><input type="checkbox" data-i="${k}">${l}</label>`).join('');
  const stats=Object.keys(STATUT);
  $('#fStat').innerHTML=stats.map(k=>
    `<label><input type="checkbox" data-s="${k}"><span class="smark" style="color:#${STATUT[k][1]}">${STATUT[k][2]||'·'}</span> ${STATUT[k][0]}</label>`).join('');
  $('#fpop').addEventListener('change',e=>{
    const cb=e.target;
    if(cb.dataset.t!==undefined){cb.checked?fTypes.add(cb.dataset.t):fTypes.delete(cb.dataset.t);}
    if(cb.dataset.i!==undefined){cb.checked?fImp.add(cb.dataset.i):fImp.delete(cb.dataset.i);}
    if(cb.dataset.s!==undefined){cb.checked?fStat.add(cb.dataset.s):fStat.delete(cb.dataset.s);}
    updateBadge();refresh();
  });
  $('#fpop').addEventListener('click',e=>{
    const b=e.target.closest('button');if(!b)return;
    if(b.dataset.all==='type'){fTypes=new Set(TYPES.map(t=>t[0]));syncChecks();}
    if(b.dataset.none==='type'){fTypes.clear();syncChecks();}
    if(b.dataset.all==='imp'){fImp=new Set(imps.map(i=>i[0]));syncChecks();}
    if(b.dataset.none==='imp'){fImp.clear();syncChecks();}
    if(b.dataset.all==='stat'){fStat=new Set(stats);syncChecks();}
    if(b.dataset.none==='stat'){fStat.clear();syncChecks();}
    updateBadge();refresh();
  });
}
function syncChecks(){
  document.querySelectorAll('#fTypes input').forEach(c=>c.checked=fTypes.has(c.dataset.t));
  document.querySelectorAll('#fImp input').forEach(c=>c.checked=fImp.has(c.dataset.i));
  document.querySelectorAll('#fStat input').forEach(c=>c.checked=fStat.has(c.dataset.s));
}
function updateBadge(){
  const n=fTypes.size+fImp.size+fStat.size;const b=$('#fBadge');
  b.textContent=n?n:'';b.classList.toggle('on',n>0);
}
$('#bFilter').onclick=()=>{$('#fpop').classList.toggle('open');$('#morePop').classList.remove('open');};
$('#bMore').onclick=()=>{$('#morePop').classList.toggle('open');$('#fpop').classList.remove('open');};
$('#morePop').addEventListener('click',e=>{if(e.target.closest('button'))$('#morePop').classList.remove('open');});
document.addEventListener('click',e=>{ // ferme les popovers si clic dehors
  if(!e.target.closest('.fwrap')){$('#fpop').classList.remove('open');$('#morePop').classList.remove('open');}
});

/* --- raccourcis clavier --- */
document.addEventListener('keydown',e=>{
  if(e.target.matches('input,textarea,select'))return;
  if(e.key==='n'){openNode();} 
  if(e.key==='Escape'){$('#ovN').classList.remove('open');$('#ovL').classList.remove('open');$('#fpop').classList.remove('open');}
  if((e.key==='Delete'||e.key==='Backspace')&&sel){delNode(sel);}
});

window.addEventListener('resize',()=>applyView());

/* --- gestion des missions --- */
$('#projSel').onchange=e=>switchProject(+e.target.value);
$('#bProjAdd').onclick=newProject;
$('#bProjDel').onclick=deleteProject;

buildFilters();
av();
st('chargement…','load');
loadProjects().then(load).then(()=>updateCount()).catch(e=>st('Erreur: '+e.message,'err'));
</script>
</body>
</html>
