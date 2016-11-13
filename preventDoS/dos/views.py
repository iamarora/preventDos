from django.shortcuts import render, redirect

import traceback
import redis

from django.conf import settings
from .models import PermanentBlockIp

from .forms import CaptchaForm

from django.http import HttpResponse, HttpResponseNotAllowed
from django.http import HttpResponseBadRequest, HttpResponseServerError

pool = redis.ConnectionPool(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)
r = redis.Redis(connection_pool=pool)
#######################################################################################
# Public Views
#######################################################################################

def index(request):
    try:
        if request.method == 'GET':
            response = checkDos(getIP(request))
            if response == True:
                return redirect('/dos/captcha')
            else:
                return HttpResponse( response, status=200, content_type="text/plain")
        else:
            return HttpResponseNotAllowed(['GET',], 'Invalid Method', content_type='text/plain')
    except Exception:
        return HttpResponseServerError(traceback.format_exc(), content_type='text/plain')


def refreshPermanentBlock(request):
    all_ips = PermanentBlockIp.objects.all()
    r.set('permanentBlockIpList', [x.ip_address for x in all_ips])
    resp = "Block list refreshed as :: " + str(r.get('permanentBlockIpList'))
    return  HttpResponse(resp, status=200, content_type="text/plain")


#View to show and validate the captcha
def showCaptcha(request):
    ip_address = getIP(request)
    if request.POST:
        form = CaptchaForm(request.POST)

        # Validate the form: the captcha field will automatically
        # check the input
        if form.is_valid():
            human = True
            r.setex(ip_address, "unblock", settings.CAPTCHALESS_TIME)
            r.delete('captcha_ctr'+ip_address)
            return redirect('/dos/')
        else:
            captcha_ctr = r.get('captcha_ctr'+ip_address)
            print "Incorrect captcha count = "+ str(captcha_ctr)
            if captcha_ctr:
                if int(captcha_ctr) >= 3:
                    r.setex(ip_address, "block", settings.TTL_TEMP_BLOCK)
                    r.delete('captcha_ctr'+ip_address)
                    return redirect('/dos')
                else:
                    captcha_ctr += 1
                    r.set('captcha_ctr'+ip_address, captcha_ctr)
            else:
                r.set('captcha_ctr'+ip_address, 1)
    else:
        form = CaptchaForm()

    return render(request, 'home.html', locals())


###################
#Private functions#
###################

#Main function called by view to return appropriate status
def checkDos(ip_address):
    #r.setex('127.0.0.1', "block", 120)
    #ip_address = '1.1.1.1'
    #r.delete('127.0.0.1')

    ip_status = r.get(ip_address)
    print ip_status
    
    if ip_status:
        if ip_status == 'block':
            return "IP has been blocked for sometime for suspicion of DoS"
        elif ip_status == 'unblock':
            return "Allowed temporary unblock without captcha"
        else:
            return checkPermanentBlock(ip_address)
    else:
        return checkPermanentBlock(ip_address)

#Prevent DOS based on Nuumber of hits from same IP within a particular amount of time.
def preventDos(ip_address):
    ctr = r.get('ctr'+ip_address)
    print "Counter in prevent = " +str(ctr)
    if ctr:
        if int(ctr) >= int(settings.NO_OF_REQ_FROM_SAME_IP):
            #show captcha, block if 3 are continously incorrect. 
            #return redirect('/dos/captcha')
            return True
        else:
            return False
    else:
        return False

#Check if the IP is in permanent block list
def checkPermanentBlock(ip_address):
    if preventDos(ip_address):
        return True

    blocklist = r.get('permanentBlockIpList') 
    if ip_address in blocklist:
        return "You are on the permanent blocklist"
    else:
        ctr = r.get('ctr'+ip_address)
        print "Counter = " +str(ctr)
        if ctr:
            ctr = int(ctr)
            ctr += 1
            r.setex('ctr'+ip_address, ctr, settings.WITHIN_TIME)
        else:        
            r.setex('ctr'+ip_address, 1, settings.WITHIN_TIME)
        return "Successful valid call!!!"

#Function to get IP from Django request object
def getIP(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
