"""Local measurements only. Successful-check ratio is not continuous uptime."""
import json,re,sqlite3,threading,time

class HealthStore:
    def __init__(self,path):
        self.path=path;self.lock=threading.RLock()
        with self.connect() as c:
            c.execute('create table if not exists samples (server text, ts real, payload text)')
            c.execute('create index if not exists sample_time on samples(server,ts)')
    def connect(self):return sqlite3.connect(str(self.path),timeout=15)
    def record(self,server,status):
        data=status.get('data') or {};now=status['checkedAt']
        with self.lock,self.connect() as c:
            previous=c.execute('select payload from samples where server=? order by ts desc limit 1',(server,)).fetchone()
            previous=json.loads(previous[0]) if previous else None
            sample=dict(ts=now,ok=status['ok'],tcpOk=status.get('tcpOk'),tcpMs=status.get('tcpMs'),durationMs=status.get('durationMs'),error=status.get('error','')[:500],cpu=data.get('cpu'),memory=data.get('memory'),disk=data.get('disk'),swap=data.get('swap'),load=data.get('load'),cores=data.get('cores'),uptime=data.get('uptime'),bootId=data.get('bootId'),awg=data.get('awg',[]),failed=data.get('failedUnits',[]),rebootRequired=data.get('rebootRequired',False))
            if isinstance(data.get('collectionOk'),dict):
                sample['collectionOk']={key:data['collectionOk'].get(key) if isinstance(data['collectionOk'].get(key),bool) else None for key in ('services','containers','awg')}
            for key in ('awgSupported','dockerSupported'):
                if key in data:sample[key]=data[key] if isinstance(data[key],bool) else None
            sample['services']=[]
            for item in data.get('services',[]):
                row={'unit':item.get('unit',''),'state':item.get('state','unknown'),'loaded':item.get('loaded',False)}
                if 'collectionOk' in item:row['collectionOk']=item['collectionOk'] if isinstance(item['collectionOk'],bool) else None
                sample['services'].append(row)
            sample['containers']=[]
            for item in data.get('containers',[]):
                row={'name':item.get('name',''),'state':item.get('state','unknown'),'description':str(item.get('description',''))[:160]}
                if isinstance(item.get('unit'),str) and re.fullmatch(r'docker:[0-9a-f]{12,64}',item['unit']):row['unit']=item['unit']
                if isinstance(item.get('awg'),dict):
                    probe=item['awg'];names=probe.get('interfaces');valid=isinstance(names,list) and len(names)<=128 and all(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}',name) for name in names)
                    row['awg']={'collectionOk':probe.get('collectionOk') is True and valid,'interfaces':sorted(set(names)) if valid else []}
                    if probe.get('error'):row['awg']['error']=str(probe['error'])[:200]
                sample['containers'].append(row)
            alerts=[]
            if not status['ok']:alerts.append(dict(level='critical',title='Нет доступа по SSH',detail=sample['error'] or 'Проверка не выполнена'))
            else:
                incomplete=[key for key,value in sample.get('collectionOk',{}).items() if value is not True]
                if incomplete:alerts.append(dict(level='warning',title='Неполная проверка служб',detail='Не удалось подтвердить состояние: '+', '.join(incomplete)))
                if sample['cpu'] is None or not sample['memory'] or not sample['disk']:alerts.append(dict(level='warning',title='Неполные метрики',detail='Часть ресурсов не удалось измерить'))
                limits=[('cpu','ЦП',85,95),('memory','Память',85,95),('disk','Диск',80,90)]
                for key,title,warn,critical in limits:
                    value=sample[key]
                    percent=(value['used']/value['total']*100 if value and isinstance(value,dict) and value.get('total') else value if isinstance(value,(int,float)) else None)
                    if percent is not None and percent>=warn:alerts.append(dict(level='critical' if percent>=critical else 'warning',title=title+': '+str(round(percent))+'%',detail='Порог '+str(critical if percent>=critical else warn)+'%; один текущий замер'))
                for unit in data.get('services',[]):
                    if unit.get('state')=='failed' and unit.get('collectionOk',True) is True:alerts.append(dict(level='critical',title='Ошибка службы',detail=unit['unit']))
                monitored={x.get('unit') for x in data.get('services',[]) if x.get('state')=='failed'}
                others=[x for x in sample['failed'] if x not in monitored]
                if others:alerts.append(dict(level='warning',title='Есть failed-службы systemd',detail=', '.join(others)))
                for container in data.get('containers',[]):
                    if 'unhealthy' in container.get('description','').lower():alerts.append(dict(level='warning',title='Контейнер unhealthy',detail=container.get('name','')))
                if sample['rebootRequired']:alerts.append(dict(level='info',title='Система запрашивает перезагрузку',detail='Перезагрузка не выполняется автоматически'))
            old_awg={x['interface']:x for x in previous.get('awg',[])} if previous else {}
            for interface in sample['awg']:
                before=old_awg.get(interface['interface']);delta=None
                comparable=previous and previous['ok'] and sample.get('collectionOk',{}).get('awg',True) is True and previous.get('collectionOk',{}).get('awg',True) is True and sample.get('bootId') and previous.get('bootId')==sample.get('bootId') and now-previous['ts']<=180 and before and interface.get('ifindex') is not None and before.get('ifindex')==interface.get('ifindex')
                if comparable:
                    current=interface['counters'].get('rx_errors');old=before['counters'].get('rx_errors')
                    if current is not None and old is not None and current>=old:delta=current-old
                interface['rxErrorsDelta']=delta
                if delta:alerts.append(dict(level='warning',title='Растёт RX errors · '+interface['interface'],detail='+'+str(delta)+' за '+str(round(now-previous['ts']))+' сек.; причина по счётчику не устанавливается'))
            sample['alerts']=alerts
            sample['cpuIntervalSeconds']=data.get('cpuIntervalSeconds')
            sample['health']='unavailable' if not status['ok'] else 'critical' if any(x['level']=='critical' for x in alerts) else 'warning' if any(x['level']=='warning' for x in alerts) else 'ok'
            c.execute('insert into samples values (?,?,?)',(server,now,json.dumps(sample,ensure_ascii=False)))
            c.execute('delete from samples where ts<?',(now-7*86400,))
            return sample
    def report(self,ids,hours=24,now=None):
        now=now or time.time();result={}
        with self.lock,self.connect() as c:
            for sid in ids:
                rows=[json.loads(x[0]) for x in c.execute('select payload from samples where server=? and ts>=? order by ts',(sid,now-hours*3600))]
                latest=c.execute('select payload from samples where server=? order by ts desc limit 1',(sid,)).fetchone()
                latest=json.loads(latest[0]) if latest else None
                stale=not latest or now-latest['ts']>150
                successes=sum(1 for x in rows if x['ok'])
                incidents=[]
                for item in rows:
                    if not item['ok']:
                        if not incidents or incidents[-1].get('recovered') or item['ts']-incidents[-1]['last']>150:
                            incidents.append(dict(start=item['ts'],last=item['ts'],checks=1,error=item.get('error',''),recovered=None))
                        else:incidents[-1]['last']=item['ts'];incidents[-1]['checks']+=1
                    elif incidents and not incidents[-1].get('recovered'):
                        incidents[-1]['recovered']=item['ts']
                points=[dict(ts=x['ts'],ok=x['ok'],tcpOk=x.get('tcpOk'),tcpMs=x.get('tcpMs'),durationMs=x.get('durationMs'),cpu=x.get('cpu'),memoryPct=(x['memory']['used']/x['memory']['total']*100 if x.get('memory') and x['memory']['total'] else None),diskPct=(x['disk']['used']/x['disk']['total']*100 if x.get('disk') and x['disk']['total'] else None),health=x['health']) for x in rows]
                result[sid]=dict(latest=latest,stale=stale,samples=points,total=len(rows),successes=successes,successRate=round(successes/len(rows)*100,2) if rows else None,first=rows[0]['ts'] if rows else None,incidents=incidents[-10:])
        return dict(servers=result,generatedAt=now,hours=hours,intervalSeconds=60,staleAfterSeconds=150)
