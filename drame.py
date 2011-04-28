'''
drame.py

Copyright 2006 Andres Riancho

This file is part of w3af, w3af.sourceforge.net .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

'''
from __future__ import with_statement

import core.controllers.outputManager as om

# options
from core.data.options.option import option
from core.data.options.optionList import optionList

from core.controllers.basePlugin.baseAuditPlugin import baseAuditPlugin
from core.data.fuzzer.fuzzer import createMutants, createRandAlpha
from core.controllers.w3afException import w3afException
import core.data.constants.dbms as dbms

import core.data.kb.knowledgeBase as kb
import core.data.kb.vuln as vuln
import core.data.constants.severity as severity

import re

from core.controllers.misc.levenshtein import relative_distance


# global variable useful for distinguishing threads
global_id = 0;

# global variable useful for distinguishing different Levenshtein distance
num = 0


class drame(baseAuditPlugin):
    '''
    Find SQL injection bugs.
    @author: Thibault Desmoulins ( http://www.desmoulins-thibault.fr/ )
    '''

    def __init__(self):
        baseAuditPlugin.__init__(self)
        
        # Internal variables
        self._listeType        = []
        self._compteur         = 0
        
        # The level used in the process of clustering
        self._level = 10

    def audit(self, freq):
        '''
        Tester les vulnerabilites d'injection SQL d'une URL
        
        @param freq: Une URL a tester
        '''
        # New audit, everything following will have global_id for identifying
        global global_id
        global_id = global_id + 1

        # Recupere la page : OK
        oResponse = self._sendMutant( freq , analyze=False ).getBody()
        
        # Recupere un tableau de string a tester
        drame_str_reject    = self.getDrameStrings("reject")
        drame_str_error     = self.getDrameStrings("error")
        drame_str_injection = self.getDrameStrings("injection")

        # REJECT URL
        mutantsReject = createMutants( freq , drame_str_reject, oResponse=oResponse )
        for mutant in mutantsReject:
            # Only spawn a thread if the mutant has a modified variable
            # that has no reported bugs in the kb
            if self._hasNoBug( 'drame' , 'drame', mutant.getURL() , mutant.getVar() ):
                # resultReject function will be the callback of this _sendMutant
                targs = (mutant,True,True,self._resultReject)
                self._tm.startFunction( target=self._sendMutant, args=targs, ownerObj=self )

        # ERROR URL
        mutantsError = createMutants( freq , drame_str_error, oResponse=oResponse )
        for mutant in mutantsError:
            if self._hasNoBug( 'drame' , 'drame', mutant.getURL() , mutant.getVar() ):
                # resultError function will be the callback of this _sendMutant
                targs = ( mutant, True, True, self._resultError )
                self._tm.startFunction( target=self._sendMutant, args=targs, ownerObj=self )

        # INJECTION URL
        mutantsInjection = createMutants( freq , drame_str_injection, oResponse=oResponse )
        for mutant in mutantsInjection:
            if self._hasNoBug( 'drame' , 'drame', mutant.getURL() , mutant.getVar() ):
                # resultInjection function will be the callback of this _sendMutant
                targs = (mutant,True,True,self._resultInjection)
                self._tm.startFunction( target=self._sendMutant, args=targs, ownerObj=self )

        self._tm.join( self )


    def extractType(self, number):
        listeType = []
        for t in self._listeType:
            if t.getIdRequest() == number:
                listeType.append(t)
        return listeType
    
        
    def getLD(self, A, B):
        global num
        num = num + 1
        
        result = int(relative_distance(A.getPage(), B.getPage())*100)
        print("\n-->(" + str(num) + ") " + str(len(A.getPage())) + " - " + str(len(B.getPage())) + " - " + str(result) )
        
        return result

    def _resultReject(self, mutant, response):
        self._compteur+=1
        p = typeURL( global_id, self._compteur, response.getURI(), 'reject', response.getBody() )
        self._listeType.append( p )

    def _resultError(self, mutant, response):
        self._compteur+=1
        p = typeURL( global_id, self._compteur, response.getURI(), 'error', response.getBody() )
        self._listeType.append( p )

    def _resultInjection(self, mutant, response):
        self._compteur+=1
        p = typeURL( global_id, self._compteur, response.getURI(), 'injection', response.getBody() )
        self._listeType.append( p )


    def end(self):
        '''
        This method is called when the plugin wont be used anymore.
        '''
        if len(self._listeType):
            for i in range(global_id+1):
                liste = self.extractType(i)
                if len(liste):
                    cl = HierarchicalClustering( liste, self.getLD )
                    clusteredData = cl.getlevel( self._level )
                    
                    print('\n\n================')
                    n = len(clusteredData)
                    for j in range(n):
                        print('\n---------' + str(j+1) + '----------\n')
                        clusteredData[j].affiche()
                        print('--------------------\n')
        
        self._tm.join( self )
        self.printUniq( kb.kb.getData( 'drame', 'drame' ), 'VAR' )
        
    
    def getDrameStrings(self, kind):
        '''
        Gets a list of strings to test against the web app.
        
        @return: A list with all drame strings to test. Example: [ '\'','\'\'']
        '''
        drame_strings = []

        if kind == "reject":
            drame_strings.append(createRandAlpha(5))
            #drame_strings.append(createRandAlpha(5))
        elif kind == "error":
            #drame_strings.append("d'z\"0")
            drame_strings.append("' or '1'=PLOOP")
            #drame_strings.append("#")
        elif kind == "injection":
            drame_strings.append("' or '1'='1")
            #drame_strings.append("' or '1'='1' #")
        
        return drame_strings
    
    def getOptions(self):
        '''
        @return: A list of option objects for this plugin.
        '''
        d1 = 'The algorithm to use in the comparison of true and false response for blind sql.'
        h1 = 'The options are: "stringEq" and "setIntersection". '
        h1 += 'Read the long description for details.'
        o1 = option('Hierarchical clustering level', self._level, d1, 'integer', help=h1)
        
        ol = optionList()
        ol.add(o1)
        return ol

    def setOptions(self, optionsMap):
        '''
        This method sets all the options that are configured using the user interface 
        generated by the framework using the result of getOptions().
        
        @parameter optionsMap: A dictionary with the options for the plugin.
        @return: No value is returned.
        ''' 
        self._level = optionsMap['Hierarchical clustering level'].getValue()

    def getPluginDeps(self):
        '''
        @return: A list with the names of the plugins that should be runned before the
        current one.
        '''
        return []
    
    def getLongDesc(self):
        '''
        @return: A DETAILED description of the plugin functions and features.
        '''
        return '''
        This plugin finds SQL injections. To find this vulnerabilities the plugin sends the string d'z"0 to every
        injection point, and searches for SQL errors in the response body.
        '''


class typeURL:
    def __init__(self, idRequest, compteur, uri, kind, page):
        self._idRequest = idRequest
        self._compteur  = compteur
        self._uri       = uri
        self._kind      = kind
        self._page      = page

    def getIdRequest(self):
        return self._idRequest

    def getPage(self):
        return self._page

    def getKind(self):
        return self._kind

    def getURI(self):
        return self._uri

    def getCompteur(self):
        return self._compteur

    def affiche(self):
        om.out.debug( '-->ID ' + str(self._idRequest) + ' - OBJET ' + str(self._compteur) + ' (' + self._kind + ') : ' + self._uri)


class Cluster:
    def __init__(self, item1, item2, distance):
        self._cluster     = []
        self._distanceMin = distance
        self._distanceMax = distance
        
        self._cluster.append(item1)
        self._cluster.append(item2)

    def joinCluster(self, otherCluster):
        items = otherCluster.getItems()
        for item in items:
            self._cluster.append(item)
        
        self.setDistanceMin(otherCluster.getDistanceMin())
        self.setDistanceMax(otherCluster.getDistanceMax())

    def estProche(self, otherCluster, level):
        minDist = self._distanceMin - level
        maxDist = self._distanceMax + level
        oMin    = otherCluster.getDistanceMin()
        oMax    = otherCluster.getDistanceMax()
        if (minDist<=oMin and oMin<=maxDist) or (minDist<=oMax and oMax<=maxDist):
            return True
        else:
            return False

    def getDistanceMin(self):
        return self._distanceMin
    
    def getDistanceMax(self):
        return self._distanceMax
    
    def getItems(self):
        return self._cluster
    
    def setDistanceMin(self, newDist):
        if newDist < self._distanceMin:
            self._distanceMin = newDist

    def setDistanceMax(self, newDist):
        if newDist > self._distanceMax:
            self._distanceMax = newDist

    def affiche(self):
        for item in self._cluster:
            item.affiche()


class HierarchicalClustering:
    def __init__(self, liste, distFunction):
        self._liste        = liste
        self._distFunction = distFunction

    def getlevel(self, level):
        clusters = self.getClusters()

        i = 0
        while i < len(clusters)-1:
            j = i + 1
            while j < len(clusters):
                if clusters[i].estProche(clusters[j], level):
                    clusters[i].joinCluster(clusters[j])
                    del clusters[j] # the next cluster is joined to that one, so we delete it
                else:
                    j = j + 1
            i = i + 1

        return clusters

    def getClusters(self):
        clusters = []
        n = len(self._liste)
        i = 0
        while i < n-1:
            j = i + 1
            while j < n:
                dist = self._distFunction(self._liste[i], self._liste[j])
                clusters.append( Cluster(self._liste[i], self._liste[j], dist) )
                j = j+ 1
            i = i + 1
        return clusters
