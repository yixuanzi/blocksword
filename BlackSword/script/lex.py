import re
text='jiangxi'
'''
regexes=[re.compile(p)
       for p in ['\(','\)','\++','\--','>','<','==','!=','=',':',#opertion char
                 '@[a-zA-Z\.]+',#protocol variable
                 '#[a-zA-Z\.]+',#protocol variable
                 '\$\w+',#rule variable
                 '".*"', #string
                 'normal','triggle','type','ip','arp','icmp','tcp','if','protocol','continuation','yes','no',#keyword
                 '[A-Za-z]\w*', #ID str
                 '[0-9]+',#int
                 ]
       ]
for regex in regexes:
    for match in regex.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            print (text[s:e])
            text=text[:s]+'\x00'*(e-s)+text[e:]
print (text)
''' 
#sort for result
def sort(result):
    l=len(result)
    if l<1:
        return
    for i in range(1,l,1):
        for j in range(1,l-i+1,1):
            if result[j-1][0]>result[j][0]:
                result[j-1],result[j]=result[j],result[j-1]
 

def lex(path):
    try:
        f=open(path)
    except:
        print ("open file failed")
        return
    try:
        r=open(path+".lex","w")
    except:
        print ("create lex file failed")
        return
    text=f.readline()
    while text:
        rs=lex_line(text)
        print (rs,file=r)
        text=f.readline()
    f.close()
    r.close()
def lex_line(text):
    result=[]
    for regex in regexes_oc:
        for match in regex.finditer(text):
            if match:
                s=match.start()
                e=match.end()
                ss=text[s:e]
                text=text[:s]+'\x00'*(e-s)+text[e:]
                tp=(s,'oc',ss)
                result.append(tp)
    
    for match in regexes_pv.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            ss=text[s:e]
            text=text[:s]+'\x00'*(e-s)+text[e:]
            tp=(s,'pv',ss)
            result.append(tp)
    for match in regexes_rv.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            ss=text[s:e]
            text=text[:s]+'\x00'*(e-s)+text[e:]
            tp=(s,'rv',ss)
            result.append(tp)
    for match in regexes_str.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            ss=text[s:e]
            text=text[:s]+'\x00'*(e-s)+text[e:]
            tp=(s,'str',ss)
            result.append(tp)
    for match in regexes_id.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            ss=text[s:e]
            text=text[:s]+'\x00'*(e-s)+text[e:]
            tp=(s,'id',ss)
            result.append(tp)
    for regex in regexes_kw:
        for match in regex.finditer(text):
            if match:
                s=match.start()
                e=match.end()
                ss=text[s:e]
                text=text[:s]+'\x00'*(e-s)+text[e:]
                tp=(s,'kw',ss)
                result.append(tp)
    for regex in regexes_fc:
        for match in regex.finditer(text):
            if match:
                s=match.start()
                e=match.end()
                ss=text[s:e]
                text=text[:s]+'\x00'*(e-s)+text[e:]
                tp=(s,'fc',ss)
                result.append(tp)

    for match in regexes_int.finditer(text):
        if match:
            s=match.start()
            e=match.end()
            ss=text[s:e]
            text=text[:s]+'\x00'*(e-s)+text[e:]
            tp=(s,'int',ss)
            result.append(tp)
    
    sort(result)
    return result
    
    
 
if __name__=='__main__':
    regexes_oc=[re.compile(p)
                for p in ['\(','\)','\++','\--','>','<','==','!=','=',':']#opertion char
                ]
    regexes_pv=re.compile('[@#][a-zA-Z\.]+')#protocol variable
                
    regexes_rv=re.compile('\$\w+')#rule variable
    
    regexes_str=re.compile('\".*\"')#string
    
    regexes_kw=[re.compile(p)
                for p in['normal','triggle','type','ip','arp','icmp','tcp','if','protocol','continuation','yes','no']#keyword
                ]
    regexes_fc=[re.compile(p)
                for p in['find','alert','log','pass','chunk']
                ]
    regexes_id=re.compile('[a-zA-Z]\w*')#id string
                
    regexes_int=re.compile('[0-9]+')
    
    lex('rule.txt')
