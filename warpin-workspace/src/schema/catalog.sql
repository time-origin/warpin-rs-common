SELECT jsonb_build_object(
 'tables', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'name',c.relname,'kind',c.relkind,'persistence',c.relpersistence,
   'options',c.reloptions,'rowSecurity',c.relrowsecurity,'forceRowSecurity',c.relforcerowsecurity,
   'rules',c.relhasrules) ORDER BY c.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname=$1
   AND c.relkind IN('r','p','v','m','f')), '[]'::jsonb),
 'columns', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'table',c.relname,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
   'dimensions',a.attndims,'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE pg_describe_object('pg_collation'::regclass,a.attcollation,0) END,'notNull',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,
   'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
   LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
   WHERE n.nspname=$1), '[]'::jsonb),
 'constraints', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'table',c.relname,'name',k.conname,'kind',k.contype,'validated',k.convalidated,
   'deferrable',k.condeferrable,'deferred',k.condeferred,'definition',pg_get_constraintdef(k.oid,true))
   ORDER BY c.relname,k.conname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_constraint k ON k.conrelid=c.oid
   WHERE n.nspname=$1), '[]'::jsonb),
 'indexes', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'table',c.relname,'name',ic.relname,'accessMethod',am.amname,
   'unique',i.indisunique,'primary',i.indisprimary,'valid',i.indisvalid,'ready',i.indisready,
   'keyCount',i.indnkeyatts,'attributeCount',i.indnatts,
   'keys',(SELECT jsonb_agg(pg_get_indexdef(i.indexrelid,p,true) ORDER BY p)
      FROM generate_series(1,i.indnatts) p),
   'predicate',pg_get_expr(i.indpred,i.indrelid)) ORDER BY c.relname,ic.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class ic ON ic.oid=i.indexrelid
   JOIN pg_am am ON am.oid=ic.relam
   WHERE n.nspname=$1), '[]'::jsonb),
 'triggers', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'table',c.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid,true))
   ORDER BY c.relname,t.tgname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_trigger t ON t.tgrelid=c.oid AND NOT t.tgisinternal
   WHERE n.nspname=$1), '[]'::jsonb)
,
 'inheritance', COALESCE((SELECT jsonb_agg(jsonb_build_object('child',child.relname,'parent',parent.relname,'childSchema',cn.nspname,'parentSchema',pn.nspname) ORDER BY cn.nspname,child.relname,pn.nspname,parent.relname)
   FROM pg_inherits i JOIN pg_class child ON child.oid=i.inhrelid JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=i.inhparent JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE (cn.nspname=$1) OR (pn.nspname=$1)), '[]'::jsonb),
 'functions', COALESCE((SELECT jsonb_agg(jsonb_build_object('name',p.proname,'owner',p.proowner,'kind',p.prokind,'securityDefiner',p.prosecdef,'configuration',p.proconfig,'acl',p.proacl,'definition',pg_get_functiondef(p.oid)) ORDER BY p.oid)
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1), '[]'::jsonb)
) AS catalog;
