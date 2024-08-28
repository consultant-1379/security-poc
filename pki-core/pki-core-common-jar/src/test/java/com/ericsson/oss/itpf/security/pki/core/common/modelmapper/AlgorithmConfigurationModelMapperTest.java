/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.util.*;

import org.junit.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;

public class AlgorithmConfigurationModelMapperTest {

	
	
	private Algorithm algorithm;
	private List<Algorithm> algorithmList;
	private AlgorithmData algorithmData;
	private List<AlgorithmData> algorithmDatas;
	
	@Before
	public void setUP(){
		algorithmList=new ArrayList<Algorithm>();
		algorithm=new Algorithm();
		algorithmDatas=new ArrayList<AlgorithmData>();
		algorithmData=new  AlgorithmData();
	}

	@Test
	public void testToAlgorithmData() {
		toAlgorithmData_Setup();
		algorithmData=AlgorithmConfigurationModelMapper.toAlgorithmData(algorithm);
		Assert.assertEquals(algorithm.getType(), algorithmData.getType());
		Assert.assertEquals(algorithm.getName(), algorithmData.getName());
	}
	
	private void toAlgorithmData_Setup(){
		algorithm.setId(12345);
		algorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
		algorithm.setName("Algorithm");
	}
	
	@Test
	public void testToAlgorithmData_ListOfAlgorithm() {
		testToAlgorithmData_ListOfAlgorithm_Setup();
		algorithmDatas=Arrays.asList(AlgorithmConfigurationModelMapper.toAlgorithmData(algorithmList));
		for(int i=0;i<algorithmDatas.size();i++){
			Assert.assertEquals(algorithmList.get(i).getType(),algorithmDatas.get(i).getType());
			Assert.assertEquals(algorithmList.get(i).getName(),algorithmDatas.get(i).getName());
		}
	}
	
	private void testToAlgorithmData_ListOfAlgorithm_Setup(){
		toAlgorithmData_Setup();
		algorithmList.add(algorithm);
	}
	
	@Test
	public void testFromAlgorithmData(){
		testFromAlgorithmData_Setup();
		algorithm=AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmData);
		Assert.assertEquals(algorithmData.getName(), algorithm.getName());
		Assert.assertEquals(algorithmData.getType(), algorithm.getType());
	}
	
	private void testFromAlgorithmData_Setup(){
		algorithmData=new AlgorithmData();
		algorithmData.setId(123);
		algorithmData.setName("ABC");
		algorithmData.setType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM);
	}
	
	@Test
	public void testFromAlgorithmData_ListOfAlgorithmData(){
		testFromAlgorithmData_ListOfAlgorithmData_Setup();
		algorithmList=AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmDatas);
		for(int i=0;i<algorithmList.size();i++){
			Assert.assertEquals(algorithmDatas.get(i).getType(),algorithmList.get(i).getType());
			Assert.assertEquals(algorithmDatas.get(i).getName(),algorithmList.get(i).getName());
		}
	}
	
	private void testFromAlgorithmData_ListOfAlgorithmData_Setup(){
		testFromAlgorithmData_Setup();
		algorithmDatas=new ArrayList<AlgorithmData>();
		algorithmDatas.add(algorithmData);
	}

}
