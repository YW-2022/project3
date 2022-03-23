#include <stdio.h>
#include <stdlib.h>
#include "vecs.h"

// Initialization
void InitMyVector(my_vector *vector)
{
	// Initialize data
	vector->curSize = 0;
	vector->maxSize = MY_VECTOR_DEF_SIZE;

	// Dynamic memory allocation using malloc()
	// The C library function void *malloc(size_t size) allocates the requested memory and returns a pointer to it.
	// void *malloc(size_t size)
	vector->data = (long *)malloc(sizeof(long) * vector->maxSize);
}

// Append value
int AppendMyVector(my_vector *m_vector, long value)
{
	// Double capacity of vector
	DoubleCapacityMyVector(m_vector);

	//printf("source-ip: %ld \n",value);
	for (int i = 0; i < m_vector->curSize; i++)
	{
		long xx = GetMyVector(m_vector, i);
		if (xx == value)
			return 1;
	}

	// Add new data to the end of the array
	m_vector->data[m_vector->curSize++] = value;
	return 0;
}

// Get value
long GetMyVector(my_vector *vector, int index)
{
	// If the input data is less than 0 or greater than the maximum storage value of the array, 
	//exit the program directly because the data is illegal.
	if (index >= vector->curSize || index < 0)
	{
		exit(1);
	} 
	// If the input is a legal data, then return the corresponding data. 
	return vector->data[index];
}

// Set the value
void SetMyVector(my_vector *vector, int index, long value)
{
	// When index greater or equals to vector's current size:
	while (index >= vector->curSize)
	{
		// Fill the array with 0 as the default value.
		AppendMyVector(vector, 0);
	}
	vector->data[index] = value;
}

// Double the capacity of vector
void DoubleCapacityMyVector(my_vector *vector)
{
	if (vector->curSize >= vector->maxSize)
	{
		// Expand the array size to twice the current size.
		vector->maxSize *= 2;
		vector->data = (long *)realloc(vector->data, sizeof(long) * vector->maxSize);
	}
}

// free()
void FreeMyVector(my_vector *vector)
{
	free(vector->data);
}